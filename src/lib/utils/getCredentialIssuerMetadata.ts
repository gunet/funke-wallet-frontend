import { OpenidCredentialIssuerMetadata, OpenidCredentialIssuerMetadataSchema } from "../schemas/OpenidCredentialIssuerMetadataSchema";
import container from "../DIContainer";
import { IHttpClient } from "../interfaces/IHttpClient";


export async function getCredentialIssuerMetadata(credentialIssuerIdentifier: string): Promise<{ metadata: OpenidCredentialIssuerMetadata }> {
    const httpClient = container.resolve<IHttpClient>('HttpClient');
    const response = await httpClient.get(`${credentialIssuerIdentifier}/.well-known/openid-credential-issuer`, {});
    const metadata = OpenidCredentialIssuerMetadataSchema.parse(response.data);
    return { metadata };
}