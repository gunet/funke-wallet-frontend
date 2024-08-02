import { IOpenID4VCIClient } from '../interfaces/IOpenID4VCIClient';
import { IHttpProxy } from '../interfaces/IHttpProxy';
import { ClientConfig } from '../types/ClientConfig';
import pkce from 'pkce-challenge';
import { IOpenID4VCIClientStateRepository } from '../interfaces/IOpenID4VCIClientStateRepository';
import { CredentialConfigurationSupported } from '../schemas/CredentialConfigurationSupportedSchema';
import { OpenID4VCIClientState } from '../types/OpenID4VCIClientState';
import { VerifiableCredentialFormat } from '../schemas/vc';
import { generateDPoP } from '../utils/dpop';
import { CredentialOfferSchema } from '../schemas/CredentialOfferSchema';
import { StorableCredential } from '../types/StorableCredential';
import * as jose from 'jose';

const redirectUri = process.env.REACT_APP_OPENID4VCI_REDIRECT_URI as string;
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

export class OpenID4VCIClient implements IOpenID4VCIClient {
	private config: ClientConfig;
	private httpProxy: IHttpProxy;
	private openID4VCIClientStateRepository: IOpenID4VCIClientStateRepository;

	private generateNonceProof: (cNonce: string, audience: string, clientId: string) => Promise<{ jws: string }>;
	private storeCredential: (c: StorableCredential) => Promise<void>;

	constructor(config: ClientConfig,
		httpProxy: IHttpProxy,
		openID4VCIClientStateRepository: IOpenID4VCIClientStateRepository,
		generateNonceProof: (cNonce: string, audience: string, clientId: string) => Promise<{ jws: string }>,
		storeCredential: (c: StorableCredential) => Promise<void>) {

		this.config = config;
		this.httpProxy = httpProxy;
		this.openID4VCIClientStateRepository = openID4VCIClientStateRepository;
		this.generateNonceProof = generateNonceProof;
		this.storeCredential = storeCredential;
	}


	async handleCredentialOffer(credentialOfferURL: string): Promise<{ url: string; client_id: string; request_uri: string; }> {
		const parsedUrl = new URL(credentialOfferURL);
		const offer = CredentialOfferSchema.parse(JSON.parse(parsedUrl.searchParams.get("credential_offer")));

		if (!offer.grants.authorization_code) {
			throw new Error("Only authorization_code grant is supported");
		}
		const selectedConfigurationId = offer.credential_configuration_ids[0];
		const selectedConfiguration = this.config.credentialIssuerMetadata.credential_configurations_supported[selectedConfigurationId];
		if (!selectedConfiguration) {
			throw new Error("Credential configuration not found");
		}
		return this.generateAuthorizationRequest(selectedConfiguration);
	}

	async getAvailableCredentialConfigurations(): Promise<Record<string, CredentialConfigurationSupported>> {
		if (!this?.config?.credentialIssuerMetadata?.credential_configurations_supported) {
			throw new Error("Credential configuration supported not found")
		}
		return this.config.credentialIssuerMetadata.credential_configurations_supported
	}

	async generateAuthorizationRequest(selectedCredentialConfigurationSupported: CredentialConfigurationSupported, userHandleB64u: string = ""): Promise<{ url: string; client_id: string; request_uri: string; }> {
		const { code_challenge, code_verifier } = await pkce();

		const formData = new URLSearchParams();

		formData.append("scope", selectedCredentialConfigurationSupported.scope);

		formData.append("response_type", "code");

		formData.append("client_id", this.config.clientId);
		formData.append("code_challenge", code_challenge);

		formData.append("code_challenge_method", "S256");

		formData.append("state", btoa(JSON.stringify({userHandleB64u: userHandleB64u})).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, ""));

		formData.append("redirect_uri", redirectUri);

		const res = await this.httpProxy.post(this.config.authorizationServerMetadata.pushed_authorization_request_endpoint, formData.toString(), {
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

		let response;
		try {
			response = await this.httpProxy.post(tokenEndpoint, formData.toString(), {
				'Content-Type': 'application/x-www-form-urlencoded',
				'DPoP': dpop
			});
		}
		catch(err) {
			console.log("failed token request")
			console.error(err);
			dpopNonceHeader = err.response.data.err.headers['dpop-nonce'];
			if (dpopNonceHeader) {
				this.handleAuthorizationResponse(url, dpopNonceHeader);
				return;
			}
			return;
		}

		console.log("Token response = ", response)

		const {
			data: { access_token, c_nonce, c_nonce_expires_in, expires_in, token_type },
		} = response;


		// Credential Request
		this.credentialRequest(response, privateKey, publicKey, flowState);
	}

	private async credentialRequest(response: any, privateKey: jose.KeyLike, publicKey: jose.KeyLike, flowState: OpenID4VCIClientState) {
		const {
			data: { access_token, c_nonce, c_nonce_expires_in, expires_in, token_type },
		} = response;
		console.log('response.data = ', response.data);
		console.log('response.headers = ', response.headers);

		// Make access_token expire sooner than subsequent c_nonces
		await sleep(10 * 1000);

		const newDPoPNonce = response.headers['dpop-nonce'];
		const credentialEndpoint = this.config.credentialIssuerMetadata.credential_endpoint;
		let fetched_c_nonce;

		// First trial on credential endpoint
		const credentialEndpointDPoP = await generateDPoP(
			privateKey,
			publicKey,
			"-BwC3ESc6acc2lTc",
			"POST",
			credentialEndpoint,
			newDPoPNonce,
			access_token
		);

		const { jws } = await this.generateNonceProof(c_nonce, this.config.credentialIssuerIdentifier, this.config.clientId);
		const credentialEndpointBody = {
			"proof": {
				"proof_type": "jwt",
				"jwt": jws,
			},
			"format": flowState.selectedCredentialConfiguration.format,
		};

		if (flowState.selectedCredentialConfiguration.format == VerifiableCredentialFormat.SD_JWT_VC) {
			credentialEndpointBody['vct'] = flowState.selectedCredentialConfiguration.vct;
		}
		else if (flowState.selectedCredentialConfiguration.format == VerifiableCredentialFormat.MSO_MDOC) {
			credentialEndpointBody['doctype'] = flowState.selectedCredentialConfiguration.doctype;
		}
		try {
			const credentialResponse = await this.httpProxy.post(credentialEndpoint, credentialEndpointBody, {
				"Authorization": `DPoP ${access_token}`,
				"dpop": credentialEndpointDPoP,
			});
			console.log("First trial - Credential response:", credentialResponse.data);
			const { credential } = credentialResponse.data;
			fetched_c_nonce = credentialResponse.data.c_nonce;
			if (credential) {
				await this.storeCredential({
					credential: credential,
					format: flowState.selectedCredentialConfiguration.format,
					...(flowState.selectedCredentialConfiguration.format === VerifiableCredentialFormat.SD_JWT_VC && { vct: flowState.selectedCredentialConfiguration.vct }),
					...(flowState.selectedCredentialConfiguration.format === VerifiableCredentialFormat.MSO_MDOC && { doctype: flowState.selectedCredentialConfiguration.doctype }),
				});
			}
		} catch (err) {
			console.error("Error during first credential issuance");
			console.error(err.response.data.err.data.error_description);
		}

		// Second trial using the same access_token, same DPoP, same proof
		try {
			console.log("Second trial - Using same access_token and DPoP");
			const credentialResponseSecondTrial = await this.httpProxy.post(credentialEndpoint, credentialEndpointBody, {
				"Authorization": `DPoP ${access_token}`,
				"dpop": credentialEndpointDPoP,
			});
			console.log("Second trial - Credential response:", credentialResponseSecondTrial.data);
			const { credential } = credentialResponseSecondTrial.data;
			fetched_c_nonce = credentialResponseSecondTrial.data.c_nonce;
			if (credential) {
				await this.storeCredential({
					credential: credential,
					format: flowState.selectedCredentialConfiguration.format,
					...(flowState.selectedCredentialConfiguration.format === VerifiableCredentialFormat.SD_JWT_VC && { vct: flowState.selectedCredentialConfiguration.vct }),
					...(flowState.selectedCredentialConfiguration.format === VerifiableCredentialFormat.MSO_MDOC && { doctype: flowState.selectedCredentialConfiguration.doctype }),
				});
			}
		} catch (err) {
			console.error("Error during second credential issuance");
			console.error('second:', err.response.data.err.data.error_description);
		}

		// Third trial using the same access_token, DPoP with new jti, new proof (with fetched c_nonce)
		let { jws: newJws } = await this.generateNonceProof(fetched_c_nonce, this.config.credentialIssuerIdentifier, this.config.clientId);
		const thirdCredentialEndpointBody = {
			"proof": {
				"proof_type": "jwt",
				"jwt": newJws,
			},
			"format": flowState.selectedCredentialConfiguration.format,
		};

		if (flowState.selectedCredentialConfiguration.format === VerifiableCredentialFormat.SD_JWT_VC) {
			thirdCredentialEndpointBody['vct'] = flowState.selectedCredentialConfiguration.vct;
		} else if (flowState.selectedCredentialConfiguration.format === VerifiableCredentialFormat.MSO_MDOC) {
			thirdCredentialEndpointBody['doctype'] = flowState.selectedCredentialConfiguration.doctype;
		}
		const thirdCredentialEndpointDPoP = await generateDPoP(
			privateKey,
			publicKey,
			"-ThirdTrialCredEndpoint",
			"POST",
			credentialEndpoint,
			newDPoPNonce,
			access_token
		);

		try {
			console.log("Third trial - Using same access_token, DPoP with new jti, new proof (with fetched c_nonce)");
			const credentialResponseThirdTrial = await this.httpProxy.post(credentialEndpoint, thirdCredentialEndpointBody, {
				"Authorization": `DPoP ${access_token}`,
				"dpop": thirdCredentialEndpointDPoP,
			});
			console.log("Third trial - Credential response:", credentialResponseThirdTrial.data);
			const { credential } = credentialResponseThirdTrial.data;
			fetched_c_nonce = credentialResponseThirdTrial.data.c_nonce;
			if (credential) {
				await this.storeCredential({
					credential: credential,
					format: flowState.selectedCredentialConfiguration.format,
					...(flowState.selectedCredentialConfiguration.format === VerifiableCredentialFormat.SD_JWT_VC && { vct: flowState.selectedCredentialConfiguration.vct }),
					...(flowState.selectedCredentialConfiguration.format === VerifiableCredentialFormat.MSO_MDOC && { doctype: flowState.selectedCredentialConfiguration.doctype }),
				});
			}
		} catch (err) {
			console.error("Error during third credential issuance");
			console.error('third: ', err.response.data.err.data.error_description);
		}

		// Fourth trial using the same access_token, same dpop, new proof (with fetched c_nonce)
		let { jws: fourthJwt } = await this.generateNonceProof(fetched_c_nonce, this.config.credentialIssuerIdentifier, this.config.clientId);
		const fourthCredentialEndpointBody = {
			"proof": {
				"proof_type": "jwt",
				"jwt": fourthJwt,
			},
			"format": flowState.selectedCredentialConfiguration.format,
		};

		if (flowState.selectedCredentialConfiguration.format === VerifiableCredentialFormat.SD_JWT_VC) {
			fourthCredentialEndpointBody['vct'] = flowState.selectedCredentialConfiguration.vct;
		} else if (flowState.selectedCredentialConfiguration.format === VerifiableCredentialFormat.MSO_MDOC) {
			fourthCredentialEndpointBody['doctype'] = flowState.selectedCredentialConfiguration.doctype;
		}

		try {
			console.log("Fourth trial - Using same access_token, same DPoP, new proof (with fetched c_nonce)");
			const credentialResponseFourthTrial = await this.httpProxy.post(credentialEndpoint, fourthCredentialEndpointBody, {
				"Authorization": `DPoP ${access_token}`,
				"dpop": thirdCredentialEndpointDPoP,
			});
			console.log("Fourth trial - Credential response:", credentialResponseFourthTrial.data);
			const { credential } = credentialResponseFourthTrial.data;
			fetched_c_nonce = credentialResponseFourthTrial.data.c_nonce;
			if (credential) {
				await this.storeCredential({
					credential: credential,
					format: flowState.selectedCredentialConfiguration.format,
					...(flowState.selectedCredentialConfiguration.format === VerifiableCredentialFormat.SD_JWT_VC && { vct: flowState.selectedCredentialConfiguration.vct }),
					...(flowState.selectedCredentialConfiguration.format === VerifiableCredentialFormat.MSO_MDOC && { doctype: flowState.selectedCredentialConfiguration.doctype }),
				});
			}
		} catch (err) {
			console.error("Error during fourth credential issuance");
			console.error('fourth: ', err.response.data.err.data.error_description);
		}

		// Fifth trial using the same EXPIRED access_token, same dpop, new proof (with fetched c_nonce)
		let { jws: fifthJwt } = await this.generateNonceProof(fetched_c_nonce, this.config.credentialIssuerIdentifier, this.config.clientId);
		const fifthCredentialEndpointBody = {
			"proof": {
				"proof_type": "jwt",
				"jwt": fifthJwt,
			},
			"format": flowState.selectedCredentialConfiguration.format,
		};

		if (flowState.selectedCredentialConfiguration.format === VerifiableCredentialFormat.SD_JWT_VC) {
			fifthCredentialEndpointBody['vct'] = flowState.selectedCredentialConfiguration.vct;
		} else if (flowState.selectedCredentialConfiguration.format === VerifiableCredentialFormat.MSO_MDOC) {
			fifthCredentialEndpointBody['doctype'] = flowState.selectedCredentialConfiguration.doctype;
		}
		setTimeout(async () => {
			try {
				console.log("Fifth trial - Using expired access_token");
				const credentialResponseExpired = await this.httpProxy.post(credentialEndpoint, fifthCredentialEndpointBody, {
					"Authorization": `DPoP ${access_token}`,
					"dpop": thirdCredentialEndpointDPoP,
				});
				console.log("Fifth trial - Credential response with expired token:", credentialResponseExpired.data);
			} catch (err) {
				console.error("Error during fifth credential issuance with expired token");
				console.error('fifth: ', err.response.data.err.data.error_description);
			}
		}, (expires_in + 3) * 1000);  // wait a bit longer than the expiration time, fetched_c_nonce shouldn't have expired yet

	}

}
