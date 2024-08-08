import { CredentialConfigurationSupported } from "../schemas/CredentialConfigurationSupportedSchema";

/**
 * serializable
 */
export class OpenID4VCIClientState {

	constructor(
		public id: string,
		public code_verifier: string,
		public selectedCredentialConfiguration: CredentialConfigurationSupported,

		// token request reletated
		public dpopPrivateKeyJwk?: JsonWebKey,
		public dpopPublicKeyJwk?: JsonWebKey,
		public dpopNonce?: string,

		// token response related
		public access_token_receival_date?: Date,
		public access_token?: string,
		public expires_in?: number, // access token expiration in seconds
		public c_nonce_receival_date?: Date,
		public c_nonce?: string,
		public c_nonce_expires_in?: number,
	) { }

	public serialize(): string {
		return JSON.stringify({
			id: this.id,
			code_verifier: this.code_verifier,
			selectedCredentialConfiguration: this.selectedCredentialConfiguration,

			dpopPrivateKeyJwk: this.dpopPrivateKeyJwk,
			dpopPublicKeyJwk: this.dpopPublicKeyJwk,
			dpopNonce: this.dpopNonce,

			access_token_receival_date: this.access_token_receival_date,
			access_token: this.access_token,
			expires_in: this.expires_in,
			c_nonce_receival_date: this.c_nonce_receival_date,
			c_nonce: this.c_nonce,
			c_nonce_expires_in: this.c_nonce_expires_in,
		});
	}

	public static deserialize(storedValue: string): OpenID4VCIClientState {
		const {
			id,
			code_verifier,
			selectedCredentialConfiguration,

			dpopPrivateKeyJwk,
			dpopPublicKeyJwk,
			dpopNonce,

			access_token_receival_date,
			access_token,
			expires_in,
			c_nonce_receival_date,
			c_nonce,
			c_nonce_expires_in
		} = JSON.parse(storedValue);
		return new OpenID4VCIClientState(id, code_verifier, selectedCredentialConfiguration, dpopPrivateKeyJwk, dpopPublicKeyJwk, dpopNonce, new Date(access_token_receival_date), access_token, expires_in, new Date(c_nonce_receival_date), c_nonce, c_nonce_expires_in);
	}
}
