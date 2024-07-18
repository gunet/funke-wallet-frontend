import container from './DIContainer';
import { HttpClient } from './services/HttpClient';
import { OpenID4VCIClientFactory } from './services/OpenID4VCIClientFactory';
import { IOpenID4VCIClient } from './interfaces/IOpenID4VCIClient';
import { IHttpClient } from './interfaces/IHttpClient';
import { ClientConfig } from './types/ClientConfig';
import { OpenID4VCIClientStateRepository } from './services/OpenID4VCIClientStateRepository';
import { IOpenID4VCIClientStateRepository } from './interfaces/IOpenID4VCIClientStateRepository';
import { getCredentialIssuerMetadata } from './utils/getCredentialIssuerMetadata';
import { getAuthorizationServerMetadata } from './utils/getAuthorizationServerMetadata';

// Register services
container.register<IHttpClient>('HttpClient', HttpClient);
container.register<IOpenID4VCIClientStateRepository>('OpenID4VCIClientStateRepository', OpenID4VCIClientStateRepository);

container.register<OpenID4VCIClientFactory>('OpenID4VCIClientFactory', OpenID4VCIClientFactory, container.resolve<IHttpClient>('HttpClient'), container.resolve<IOpenID4VCIClientStateRepository>('OpenID4VCIClientStateRepository'));

const openID4VCIClientMap = new Map<string, IOpenID4VCIClient>();

async function initialize() {
	const clientConfigs: ClientConfig[] = [
		{
			clientId: 'fed79862-af36-4fee-8e64-89e3c91091ed',
			credentialIssuerIdentifier: 'https://demo.pid-issuer.bundesdruckerei.de/c',
			credentialIssuerMetadata: (await getCredentialIssuerMetadata('https://demo.pid-issuer.bundesdruckerei.de/c')).metadata,
			authorizationServerMetadata: (await getAuthorizationServerMetadata('https://demo.pid-issuer.bundesdruckerei.de/c')).authzServeMetadata,
		},
	];

	const openID4VCIClientFactory = container.resolve<OpenID4VCIClientFactory>('OpenID4VCIClientFactory');

	for (const config of clientConfigs) {
		const openID4VCIClient = openID4VCIClientFactory.createClient(config);
		openID4VCIClientMap.set(config.clientId, openID4VCIClient);
	}
}

initialize().catch((err) => null);

export {
	openID4VCIClientMap
}
