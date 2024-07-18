export interface IOpenID4VCIClient {
	generateAuthorizationRequest(): Promise<{ url: string, request_uri: string }>;
}