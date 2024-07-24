import { OpenID4VCIClient } from './OpenID4VCIClient';
import { IHttpProxy } from '../interfaces/IHttpProxy';
import { ClientConfig } from '../types/ClientConfig';
import { IOpenID4VCIClientStateRepository } from '../interfaces/IOpenID4VCIClientStateRepository';
import { StorableCredential } from '../types/StorableCredential';

export class OpenID4VCIClientFactory {
	private httpProxy: IHttpProxy;
	private openID4VCIClientStateRepository: IOpenID4VCIClientStateRepository;

	private generateNonceProof: (cNonce: string, audience: string, clientId: string) => Promise<{ jws: string }>;
	private storeCredential: (c: StorableCredential) => Promise<void>;

	constructor(httpProxy: IHttpProxy, openID4VCIClientStateRepository: IOpenID4VCIClientStateRepository, generateNonceProof: (cNonce: string, audience: string, clientId: string) => Promise<{ jws: string }>, storeCredential: (c: StorableCredential) => Promise<void>) {
		this.httpProxy = httpProxy;
		this.openID4VCIClientStateRepository = openID4VCIClientStateRepository;
		this.generateNonceProof = generateNonceProof;
		this.storeCredential = storeCredential;
	}

	createClient(config: ClientConfig): OpenID4VCIClient {
		return new OpenID4VCIClient(config, this.httpProxy, this.openID4VCIClientStateRepository, this.generateNonceProof, this.storeCredential);
	}
}