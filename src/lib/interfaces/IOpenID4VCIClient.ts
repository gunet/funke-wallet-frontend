import { CredentialConfigurationSupported } from "../schemas/CredentialConfigurationSupportedSchema";

export interface IOpenID4VCIClient {
	getAvailableCredentialConfigurations(): Promise<Record<string, CredentialConfigurationSupported>>;
	generateAuthorizationRequest(selectedCredentialConfigurationSupported: CredentialConfigurationSupported): Promise<{ url: string, request_uri: string }>;
	handleAuthorizationResponse(url: string): Promise<void>;
}