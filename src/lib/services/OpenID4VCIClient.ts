import { IOpenID4VCIClient } from '../interfaces/IOpenID4VCIClient';
import { IHttpClient } from '../interfaces/IHttpClient';
import { ClientConfig } from '../types/ClientConfig';
import pkce from 'pkce-challenge';
import { IOpenID4VCIClientStateRepository } from '../interfaces/IOpenID4VCIClientStateRepository';
import { CredentialConfigurationSupported } from '../schemas/CredentialConfigurationSupportedSchema';
import { OpenID4VCIClientState } from '../types/OpenID4VCIClientState';
import * as jose from 'jose';
import { VerifiableCredentialFormat } from '../schemas/vc';
import { generateDPoP } from '../utils/dpop';
import { parseCredential } from '../../functions/parseCredential';
import axios from 'axios';

const redirectUri = process.env.REACT_APP_OPENID4VCI_REDIRECT_URI as string;
// @ts-ignore
const walletBackendServerUrl = process.env.REACT_APP_WALLET_BACKEND_URL;

export class OpenID4VCIClient implements IOpenID4VCIClient {
	private config: ClientConfig;
	private httpClient: IHttpClient;
	private openID4VCIClientStateRepository: IOpenID4VCIClientStateRepository;

	constructor(config: ClientConfig, httpClient: IHttpClient, openID4VCIClientStateRepository: IOpenID4VCIClientStateRepository) {
		this.config = config;
		this.httpClient = httpClient;
		this.openID4VCIClientStateRepository = openID4VCIClientStateRepository;
	}


	async getAvailableCredentialConfigurations(): Promise<Record<string, CredentialConfigurationSupported>> {
		if (!this?.config?.credentialIssuerMetadata?.credential_configurations_supported) {
			throw new Error("Credential configuration supported not found")
		}
		return this.config.credentialIssuerMetadata.credential_configurations_supported
	}

	async generateAuthorizationRequest(selectedCredentialConfigurationSupported: CredentialConfigurationSupported): Promise<{ url: string; client_id: string; request_uri: string; }> {
		const { code_challenge, code_verifier } = await pkce();

		const formData = new URLSearchParams();

		formData.append("scope", selectedCredentialConfigurationSupported.scope);

		formData.append("response_type", "code");

		formData.append("client_id", this.config.clientId);
		formData.append("code_challenge", code_challenge);
		
		formData.append("code_challenge_method", "S256");

		formData.append("redirect_uri", redirectUri);

		const res = await this.httpClient.post(this.config.authorizationServerMetadata.pushed_authorization_request_endpoint, formData.toString(), {
			'Content-Type': 'application/x-www-form-urlencoded;charset=ISO-8859-1'
		});

		
		const { request_uri, expires_in } = res.data;
		const authorizationRequestURL = `${this.config.authorizationServerMetadata.authorization_endpoint}?request_uri=${request_uri}&client_id=${this.config.clientId}`

		await this.openID4VCIClientStateRepository.store(new OpenID4VCIClientState(code_verifier, selectedCredentialConfigurationSupported));

		return {
			url: authorizationRequestURL,
			request_uri,
			client_id: this.config.clientId,
		}
	}

	async handleAuthorizationResponse(url: string, dpopNonceHeader?: string) {
		const parsedUrl = new URL(url);

		const code = parsedUrl.searchParams.get('code');
		console.log("DPOP nonce header = ", dpopNonceHeader)
		if (!code) {
			throw new Error("Could not handle authorization response");
		}


		// Token Request
		const tokenEndpoint = this.config.authorizationServerMetadata.token_endpoint;

		const { privateKey, publicKey } = await jose.generateKeyPair('ES256'); // keypair for dpop
		const dpop = await generateDPoP(
			privateKey,
			publicKey,
			"-BwC3ESc6acc2lTc",
			"POST",
			tokenEndpoint,
			dpopNonceHeader
		);

		const flowState = await this.openID4VCIClientStateRepository.retrieve();

		const formData = new URLSearchParams();
		formData.append('grant_type', 'authorization_code');
		formData.append('code', code);
		formData.append('code_verifier', flowState.code_verifier);
		formData.append('redirect_uri', redirectUri);

		const response = await this.httpClient.post(tokenEndpoint, formData.toString(), {
			'Content-Type': 'application/x-www-form-urlencoded',
			'DPoP': dpop
		});

		console.log("Token response = ", response)

		const {
			data: { access_token, c_nonce, c_nonce_expires_in, expires_in, token_type },
		} = response;


		// Credential Request
		const newDPoPNonce = response.headers['dpop-nonce'];
		const credentialEndpoint = this.config.credentialIssuerMetadata.credential_endpoint;
		const credentialEndpointDPoP = await generateDPoP(
			privateKey,
			publicKey,
			"-BwC3ESc6acc2lTc",
			"POST",
			credentialEndpoint,
			newDPoPNonce,
			access_token
		);

		// TODO: USE wallet keys to sign this proof and not the dpop keypair
		const proof = await new jose.SignJWT({
				"iss": this.config.clientId,
				"aud": this.config.credentialIssuerIdentifier,
				"nonce": c_nonce
			})
			.setIssuedAt()
			.setProtectedHeader({
				"typ": "openid4vci-proof+jwt",
				"alg": "ES256",
				"jwk": await jose.exportJWK(publicKey)
			})
			.sign(privateKey);

		const credentialEndpointBody = {
			"proof": {
				"proof_type": "jwt",
				"jwt": proof,
			},
			"format": flowState.selectedCredentialConfiguration.format,
		};

		if (flowState.selectedCredentialConfiguration.format == VerifiableCredentialFormat.SD_JWT_VC) {
			credentialEndpointBody['vct'] = flowState.selectedCredentialConfiguration.vct;
		}
		else if (flowState.selectedCredentialConfiguration.format == VerifiableCredentialFormat.MSO_MDOC) {
			credentialEndpointBody['doctype'] = flowState.selectedCredentialConfiguration.doctype;
		}

		const credentialResponse = await this.httpClient.post(credentialEndpoint, credentialEndpointBody, { 
			"Authorization": `DPoP ${access_token}`,
			"dpop": credentialEndpointDPoP,
		});
		const { credential } = credentialResponse.data;
		console.log("Credential = ", credential)

		try {
			const { c_nonce, c_nonce_expires_in } = credentialResponse.data;
			const parsedCredential = await parseCredential(credential);
			console.log("parsed cred")
			console.log(parsedCredential)
		}
		catch(err) {
			if (flowState.selectedCredentialConfiguration.format == VerifiableCredentialFormat.MSO_MDOC) {
				const response = await axios.post(walletBackendServerUrl + '/utils/mdl/parse', {
					credential,
					doc_type: flowState.selectedCredentialConfiguration.doctype
				}, {
					headers: {
						Authorization: `Bearer ${JSON.parse(sessionStorage.getItem('appToken'))}`
					}
				});
				console.log("MDL parsing = ", response.data.namespace)
			}

		}


		console.log("Credential response = ", credentialResponse);
	}
}



