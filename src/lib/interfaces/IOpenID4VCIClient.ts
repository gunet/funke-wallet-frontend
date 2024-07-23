import { CredentialConfigurationSupported } from "../schemas/CredentialConfigurationSupportedSchema";

export interface IOpenID4VCIClient {
	getAvailableCredentialConfigurations(): Promise<Record<string, CredentialConfigurationSupported>>;
	generateAuthorizationRequest(selectedCredentialConfigurationSupported: CredentialConfigurationSupported): Promise<{ url: string, client_id: string, request_uri: string }>;
	handleAuthorizationResponse(url: string, dpopNonceHeader?: string): Promise<void>;
}