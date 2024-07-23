import { IHttpClient } from "../interfaces/IHttpClient";
import { IOpenID4VCIHelper } from "../interfaces/IOpenID4VCIHelper";
import { OpenidAuthorizationServerMetadata, OpenidAuthorizationServerMetadataSchema } from "../schemas/OpenidAuthorizationServerMetadataSchema";
import { OpenidCredentialIssuerMetadata, OpenidCredentialIssuerMetadataSchema } from "../schemas/OpenidCredentialIssuerMetadataSchema";


export class OpenID4VCIHelper implements IOpenID4VCIHelper {

    httpClient: IHttpClient;
    constructor(httpClient: IHttpClient) {
        this.httpClient = httpClient;
    }
    async getAuthorizationServerMetadata(credentialIssuerIdentifier: string): Promise<{ authzServeMetadata: OpenidAuthorizationServerMetadata }> {
		const response = await this.httpClient.get(`${credentialIssuerIdentifier}/.well-known/oauth-authorization-server`, {});
		const authzServeMetadata = OpenidAuthorizationServerMetadataSchema.parse(response.data);
		return { authzServeMetadata };
	}

	async getCredentialIssuerMetadata(credentialIssuerIdentifier: string): Promise<{ metadata: OpenidCredentialIssuerMetadata }> {
		const response = await this.httpClient.get(`${credentialIssuerIdentifier}/.well-known/openid-credential-issuer`, {});
		const metadata = OpenidCredentialIssuerMetadataSchema.parse(response.data);
		return { metadata };
	}

}