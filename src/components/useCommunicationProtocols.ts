import { base64url } from "jose";
import { useEffect, useMemo, useState } from "react";
import { DIContainer } from "../lib/DIContainer";
import { IHttpProxy } from "../lib/interfaces/IHttpProxy";
import { IOpenID4VCIClient } from "../lib/interfaces/IOpenID4VCIClient";
import { IOpenID4VCIClientStateRepository } from "../lib/interfaces/IOpenID4VCIClientStateRepository";
import { IOpenID4VCIHelper } from "../lib/interfaces/IOpenID4VCIHelper";
import { HttpProxy } from "../lib/services/HttpProxy";
import { OpenID4VCIClientFactory } from "../lib/services/OpenID4VCIClientFactory";
import { OpenID4VCIClientStateRepository } from "../lib/services/OpenID4VCIClientStateRepository";
import { OpenID4VCIHelper } from "../lib/services/OpenID4VCIHelper";
import { ClientConfig } from "../lib/types/ClientConfig";
import { useLocalStorageKeystore } from "../services/LocalStorageKeystore";
import { StorableCredential } from "../lib/types/StorableCredential";
import { useApi } from "../api";



export function useCommunicationProtocols() {

	const api = useApi();
	const keystore = useLocalStorageKeystore();
	const [openID4VCIClients, setOpenID4VCIClients] = useState<{ [x: string]: IOpenID4VCIClient }>({});

	const trustedCredentialIssuers = JSON.parse(new TextDecoder().decode(base64url.decode(process.env.REACT_APP_REGISTERED_CREDENTIAL_ISSUERS_JSON_B64U)));
	const container = new DIContainer();
	// Register services

	container.register<IHttpProxy>('HttpProxy', HttpProxy);
	container.register<IOpenID4VCIClientStateRepository>('OpenID4VCIClientStateRepository', OpenID4VCIClientStateRepository);
	container.register<IOpenID4VCIHelper>('OpenID4VCIHelper', OpenID4VCIHelper, container.resolve<IHttpProxy>('HttpProxy'));

	container.register<OpenID4VCIClientFactory>('OpenID4VCIClientFactory', OpenID4VCIClientFactory,
		container.resolve<IHttpProxy>('HttpProxy'),
		container.resolve<IOpenID4VCIClientStateRepository>('OpenID4VCIClientStateRepository'),
		async (cNonce: string, audience: string, clientId: string): Promise<{ jws: string }> => {
			const { proof_jwt } = await keystore.generateOpenid4vciProof(cNonce, audience, clientId)
			return { jws: proof_jwt };
		},
		async (c: StorableCredential) => {
			await api.post('/storage/vc', {
				...c
			});
		});


	const httpProxy = container.resolve<IHttpProxy>('HttpProxy');
	const helper = container.resolve<IOpenID4VCIHelper>('OpenID4VCIHelper');

	async function initialize() {
		let open4VCIClientsJson: { [x: string]: IOpenID4VCIClient } = {};

		let clientConfigs: ClientConfig[] = await Promise.all(trustedCredentialIssuers.map(async (credentialIssuer) => {
			const [authorizationServerMetadata, credentialIssuerMetadata] = await Promise.all([
				helper.getAuthorizationServerMetadata(credentialIssuer.credential_issuer_identifier).catch((err) => null),
				helper.getCredentialIssuerMetadata(credentialIssuer.credential_issuer_identifier).catch((err) => null),
			]);
			if (!authorizationServerMetadata || !credentialIssuerMetadata) {
				return null;
			}
			return {
				clientId: credentialIssuer.client_id,
				credentialIssuerIdentifier: credentialIssuer.credential_issuer_identifier,
				credentialIssuerMetadata: credentialIssuerMetadata.metadata,
				authorizationServerMetadata: authorizationServerMetadata.authzServeMetadata,
			}
		}));
		
		clientConfigs = clientConfigs.filter((conf) => conf != null);


		console.log("Client configs = ", clientConfigs)
		const openID4VCIClientFactory = container.resolve<OpenID4VCIClientFactory>('OpenID4VCIClientFactory');

		for (const config of clientConfigs) {
			const openID4VCIClient = openID4VCIClientFactory.createClient(config);
			open4VCIClientsJson[config.credentialIssuerIdentifier] = openID4VCIClient;
			console.log("Added client for " + config.credentialIssuerIdentifier)
		}
		return { open4VCIClientsJson };
	}

	useEffect(() => {
		initialize().then(({ open4VCIClientsJson }) => {
			setOpenID4VCIClients(open4VCIClientsJson);
		});
	}, [])

	return useMemo(() => {
		return {
			openID4VCIClients: openID4VCIClients,
			openID4VCIHelper: helper,
			httpProxy: httpProxy
		}
	}, [openID4VCIClients]);
}
