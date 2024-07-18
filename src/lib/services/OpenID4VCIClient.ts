import { IOpenID4VCIClient } from '../interfaces/IOpenID4VCIClient';
import { IHttpClient } from '../interfaces/IHttpClient';
import { ClientConfig } from '../types/ClientConfig';
import pkce from 'pkce-challenge';
import { IOpenID4VCIClientStateRepository } from '../interfaces/IOpenID4VCIClientStateRepository';
import { CredentialConfigurationSupported } from '../schemas/CredentialConfigurationSupportedSchema';

const redirectUri = process.env.REACT_APP_OPENID4VCI_REDIRECT_URI as string;

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

	async generateAuthorizationRequest(selectedCredentialConfigurationSupported: CredentialConfigurationSupported): Promise<{ url: string; request_uri: string; }> {
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
		return {
			url: authorizationRequestURL,
			request_uri,
		}
	}

	async handleAuthorizationResponse(url: string) {
		const parsedUrl = new URL(url);

		const code = parsedUrl.searchParams.get('code');
		if (!code) {
			throw new Error("Could not handle authorization response");
		}
	}
}