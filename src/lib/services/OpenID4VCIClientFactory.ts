import { OpenID4VCIClient } from './OpenID4VCIClient';
import { IHttpClient } from '../interfaces/IHttpClient';
import { ClientConfig } from '../types/ClientConfig';
import { IOpenID4VCIClientStateRepository } from '../interfaces/IOpenID4VCIClientStateRepository';

export class OpenID4VCIClientFactory {
	private httpClient: IHttpClient;
	private openID4VCIClientStateRepository: IOpenID4VCIClientStateRepository;

	constructor(httpClient: IHttpClient, openID4VCIClientStateRepository: IOpenID4VCIClientStateRepository) {
		this.httpClient = httpClient;
		this.openID4VCIClientStateRepository = openID4VCIClientStateRepository;
	}

	createClient(config: ClientConfig): OpenID4VCIClient {
		return new OpenID4VCIClient(config, this.httpClient, this.openID4VCIClientStateRepository);
	}
}