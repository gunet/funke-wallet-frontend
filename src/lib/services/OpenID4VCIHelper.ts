import { IHttpProxy } from "../interfaces/IHttpProxy";
import { IOpenID4VCIHelper } from "../interfaces/IOpenID4VCIHelper";
import { OpenidAuthorizationServerMetadata, OpenidAuthorizationServerMetadataSchema } from "../schemas/OpenidAuthorizationServerMetadataSchema";
import { OpenidCredentialIssuerMetadata, OpenidCredentialIssuerMetadataSchema } from "../schemas/OpenidCredentialIssuerMetadataSchema";


export class OpenID4VCIHelper implements IOpenID4VCIHelper {

    private httpProxy: IHttpProxy;
    constructor(httpProxy: IHttpProxy) {
        this.httpProxy = httpProxy;
    }
    async getAuthorizationServerMetadata(credentialIssuerIdentifier: string): Promise<{ authzServeMetadata: OpenidAuthorizationServerMetadata }> {
		const response = await this.httpProxy.get(`${credentialIssuerIdentifier}/.well-known/oauth-authorization-server`, {});
		const authzServeMetadata = OpenidAuthorizationServerMetadataSchema.parse(response.data);
		return { authzServeMetadata };
	}

	async getCredentialIssuerMetadata(credentialIssuerIdentifier: string): Promise<{ metadata: OpenidCredentialIssuerMetadata }> {
		const response = await this.httpProxy.get(`${credentialIssuerIdentifier}/.well-known/openid-credential-issuer`, {});
		const metadata = OpenidCredentialIssuerMetadataSchema.parse(response.data);
		return { metadata };
	}

}