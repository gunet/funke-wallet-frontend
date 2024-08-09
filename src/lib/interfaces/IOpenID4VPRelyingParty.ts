export interface IOpenID4VPRelyingParty {
	handleAuthorizationRequest(url: string): Promise<{ conformantCredentialsMap: Map<string, string[]>, verifierDomainName: string } | { err: "INSUFFICIENT_CREDENTIALS" | "MISSING_PRESENTATION_DEFINITION_URI" }>;
	sendAuthorizationResponse(selectionMap: Map<string, string>): Promise<{ url?: string }>;
}
