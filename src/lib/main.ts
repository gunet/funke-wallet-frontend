import container from './DIContainer';
import { HttpClient } from './services/HttpClient';
import { OpenID4VCIClientFactory } from './services/OpenID4VCIClientFactory';
import { IOpenID4VCIClient } from './interfaces/IOpenID4VCIClient';
import { IHttpClient } from './interfaces/IHttpClient';
import { ClientConfig } from './types/ClientConfig';
import { OpenID4VCIClientStateRepository } from './services/OpenID4VCIClientStateRepository';
import { IOpenID4VCIClientStateRepository } from './interfaces/IOpenID4VCIClientStateRepository';

// Register services
container.register<IHttpClient>('HttpClient', HttpClient);
container.register<IOpenID4VCIClientStateRepository>('OpenID4VCIClientStateRepository', OpenID4VCIClientStateRepository);

container.register<OpenID4VCIClientFactory>('OpenID4VCIClientFactory', OpenID4VCIClientFactory, container.resolve<IHttpClient>('HttpClient'), container.resolve<IOpenID4VCIClientStateRepository>('OpenID4VCIClientStateRepository'));

const clientConfigs: ClientConfig[] = [
	{
		clientId: 'client-id-1',
		credentialIssuerIdentifier: 'https://example.com/oauth/token1',
		credentialIssuerMetadata: '',
		authorizationServerMetadata: '',
	},
];

const openID4VCIClientFactory = container.resolve<OpenID4VCIClientFactory>('OpenID4VCIClientFactory');


const openID4VCIClientMap = new Map<string, IOpenID4VCIClient>();

for (const config of clientConfigs) {
	const openID4VCIClient = openID4VCIClientFactory.createClient(config);
	openID4VCIClientMap.set(config.credentialIssuerIdentifier, openID4VCIClient);
}

export {
	openID4VCIClientMap
}
