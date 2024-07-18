import { OpenidAuthorizationServerMetadata, OpenidAuthorizationServerMetadataSchema } from "../schemas/OpenidAuthorizationServerMetadataSchema";
import container from "../DIContainer";
import { IHttpClient } from "../interfaces/IHttpClient";


export async function getAuthorizationServerMetadata(credentialIssuerIdentifier: string): Promise<{ authzServeMetadata: OpenidAuthorizationServerMetadata }> {
    const httpClient = container.resolve<IHttpClient>('HttpClient');
    const response = await httpClient.get(`${credentialIssuerIdentifier}/.well-known/oauth-authorization-server`, {});
    const authzServeMetadata = OpenidAuthorizationServerMetadataSchema.parse(response.data);
    return { authzServeMetadata };
}