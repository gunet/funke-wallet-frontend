import { IOpenID4VCIClient } from '../interfaces/IOpenID4VCIClient';
import { IHttpClient } from '../interfaces/IHttpClient';
import { ClientConfig } from '../types/ClientConfig';
import pkce from 'pkce-challenge';
import { IOpenID4VCIClientStateRepository } from '../interfaces/IOpenID4VCIClientStateRepository';

export class OpenID4VCIClient implements IOpenID4VCIClient {
	private config: ClientConfig;
	private httpClient: IHttpClient;
	private openID4VCIClientStateRepository: IOpenID4VCIClientStateRepository;

	constructor(config: ClientConfig, httpClient: IHttpClient, openID4VCIClientStateRepository: IOpenID4VCIClientStateRepository) {
		this.config = config;
		this.httpClient = httpClient;
		this.openID4VCIClientStateRepository = openID4VCIClientStateRepository;
	}

	async generateAuthorizationRequest(): Promise<{ url: string; request_uri: string; }> {
		const { code_challenge, code_verifier } = await pkce();
	}
}