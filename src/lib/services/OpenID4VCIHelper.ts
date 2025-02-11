import { IHttpProxy } from "../interfaces/IHttpProxy";
import { IOpenID4VCIHelper } from "../interfaces/IOpenID4VCIHelper";
import { OpenidAuthorizationServerMetadata, OpenidAuthorizationServerMetadataSchema } from "../schemas/OpenidAuthorizationServerMetadataSchema";
import { OpenidCredentialIssuerMetadata, OpenidCredentialIssuerMetadataSchema } from "../schemas/OpenidCredentialIssuerMetadataSchema";


export class OpenID4VCIHelper implements IOpenID4VCIHelper {

	constructor(
		private httpProxy: IHttpProxy
	) { }
	async getAuthorizationServerMetadata(credentialIssuerIdentifier: string): Promise<{ authzServeMetadata: OpenidAuthorizationServerMetadata }> {
		try {
			const response = await this.httpProxy.get(`${credentialIssuerIdentifier}/.well-known/oauth-authorization-server`, {});
			const authzServeMetadata = OpenidAuthorizationServerMetadataSchema.parse(response.data);
			return { authzServeMetadata };
		}
		catch(err) {
			throw new Error("Couldn't get Authorization Server Metadata");
		}
	}

	async getCredentialIssuerMetadata(credentialIssuerIdentifier: string): Promise<{ metadata: OpenidCredentialIssuerMetadata }> {
		try {
			const response = await this.httpProxy.get(`${credentialIssuerIdentifier}/.well-known/openid-credential-issuer`, {});
			const metadata = OpenidCredentialIssuerMetadataSchema.parse(response.data);
			return { metadata };
		}
		catch(err) {
			throw new Error("Couldn't get Credential Issuer Metadata");
		}

	}

}
