import { DIContainer } from './DIContainer';
import { HttpClient } from './services/HttpClient';
import { OpenID4VCIClientFactory } from './services/OpenID4VCIClientFactory';
import { IOpenID4VCIClient } from './interfaces/IOpenID4VCIClient';
import { IHttpClient } from './interfaces/IHttpClient';
import { ClientConfig } from './types/ClientConfig';
import { OpenID4VCIClientStateRepository } from './services/OpenID4VCIClientStateRepository';
import { IOpenID4VCIClientStateRepository } from './interfaces/IOpenID4VCIClientStateRepository';
import { IOpenID4VCIHelper } from './interfaces/IOpenID4VCIHelper';
import { OpenID4VCIHelper } from './services/OpenID4VCIHelper';
import { base64url } from 'jose';

const trustedCredentialIssuers = JSON.parse(new TextDecoder().decode(base64url.decode(process.env.REACT_APP_REGISTERED_CREDENTIAL_ISSUERS_JSON_B64U)));

const container = new DIContainer();
// Register services
container.register<IHttpClient>('HttpClient', HttpClient);
container.register<IOpenID4VCIClientStateRepository>('OpenID4VCIClientStateRepository', OpenID4VCIClientStateRepository);
container.register<IOpenID4VCIHelper>('OpenID4VCIHelper', OpenID4VCIHelper, container.resolve<IHttpClient>('HttpClient'));

container.register<OpenID4VCIClientFactory>('OpenID4VCIClientFactory', OpenID4VCIClientFactory, container.resolve<IHttpClient>('HttpClient'), container.resolve<IOpenID4VCIClientStateRepository>('OpenID4VCIClientStateRepository'));

const openID4VCIClientMap = new Map<string, IOpenID4VCIClient>();

const helper = container.resolve<OpenID4VCIHelper>('OpenID4VCIHelper');

async function initialize() {
	const clientConfigs: ClientConfig[] = await Promise.all(trustedCredentialIssuers.map(async (credentialIssuer) => {
		const [authorizationServerMetadata, credentialIssuerMetadata] = await Promise.all([
			helper.getAuthorizationServerMetadata(credentialIssuer.credential_issuer_identifier),
			helper.getCredentialIssuerMetadata(credentialIssuer.credential_issuer_identifier),
		]);
		return {
			clientId: credentialIssuer.client_id,
			credentialIssuerIdentifier: credentialIssuer.credential_issuer_identifier,
			credentialIssuerMetadata: credentialIssuerMetadata.metadata,
			authorizationServerMetadata: authorizationServerMetadata.authzServeMetadata,
		}
	}));
	const openID4VCIClientFactory = container.resolve<OpenID4VCIClientFactory>('OpenID4VCIClientFactory');

	console.log("initializing = ")
	for (const config of clientConfigs) {
		const openID4VCIClient = openID4VCIClientFactory.createClient(config);
		openID4VCIClientMap.set(config.credentialIssuerIdentifier, openID4VCIClient);
		console.log("Added client for " + config.credentialIssuerIdentifier)
	}
}

initialize().catch((err) => {
	console.error("Error during container initialization")
	console.error(err)
});

export {
	container,
	openID4VCIClientMap
}
