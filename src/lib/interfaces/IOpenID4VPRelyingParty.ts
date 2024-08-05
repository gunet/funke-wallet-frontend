export interface IOpenID4VPRelyingParty {
	handleAuthorizationRequest(url: string): Promise<{ conformantCredentialsMap: Map<string, string[]>, verifierDomainName: string } | { err: "INSUFFICIENT_CREDENTIALS" }>;
	sendAuthorizationResponse(selectionMap: Map<string, string>): Promise<{ url?: string }>;
}
