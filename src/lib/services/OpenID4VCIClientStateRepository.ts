import { IOpenID4VCIClientStateRepository } from "../interfaces/IOpenID4VCIClientStateRepository";
import { OpenID4VCIClientState } from "../types/OpenID4VCIClientState";


export class OpenID4VCIClientStateRepository implements IOpenID4VCIClientStateRepository {
	
	private key = "openid4vci_client_state";
	
	async store(s: OpenID4VCIClientState): Promise<void> {
		const x = s.serialize();
		/// store in index db
		throw new Error("Not impl")
	}

	async retrieve(): Promise<OpenID4VCIClientState> {
		throw new Error("Method not implemented.");
	}

}