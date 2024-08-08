import { IOpenID4VCIClientStateRepository } from "../interfaces/IOpenID4VCIClientStateRepository";
import { OpenID4VCIClientState } from "../types/OpenID4VCIClientState";


export class OpenID4VCIClientStateRepository implements IOpenID4VCIClientStateRepository {

	private baseKey = "openid4vci_client_state:";

	constructor() {
		if (!localStorage.getItem('openid4vci_client_state:ids')) {
			localStorage.setItem('openid4vci_client_state:ids', JSON.stringify([]));
		}
	}

	async store(id: string, s: OpenID4VCIClientState): Promise<void> {
		const x = s.serialize();
		localStorage.setItem(this.baseKey + id, x);

		const idArray = JSON.parse(localStorage.getItem('openid4vci_client_state:ids')) as Array<string>;
		if (!idArray.includes(id)) {
			idArray.push(id);
		}
		localStorage.setItem('openid4vci_client_state:ids', JSON.stringify(idArray));
	}

	async retrieve(id: string): Promise<OpenID4VCIClientState> {
		return OpenID4VCIClientState.deserialize(localStorage.getItem(this.baseKey + id))
	}

	async getAllStates(): Promise<OpenID4VCIClientState[]> {
		await this.cleanupExpired();
		return Promise.all(
			(JSON.parse(localStorage.getItem('openid4vci_client_state:ids')) as Array<string>).map(async (id) =>
				this.retrieve(id)
			)
		);
	}

	private async deleteState(id: string): Promise<void> {
		const idArray = JSON.parse(localStorage.getItem('openid4vci_client_state:ids')) as Array<string>;
		if (idArray.includes(id)) {
			const newIdArray = idArray.filter((x) => x != id)
			localStorage.setItem('openid4vci_client_state:ids', JSON.stringify(newIdArray));
			localStorage.removeItem(this.baseKey + id);
		}
	}

	async cleanupExpired(): Promise<void> {
		const idArray = JSON.parse(localStorage.getItem('openid4vci_client_state:ids')) as Array<string>;
		await Promise.all(idArray.map(async (id) => {
			const s = await this.retrieve(id);
			if (Math.floor(new Date(s.access_token_receival_date).getTime() / 1000) + s.expires_in < Math.floor(new Date().getTime() / 1000) ||
					Math.floor(new Date(s.c_nonce_receival_date).getTime() / 1000) + s.c_nonce_expires_in < Math.floor(new Date().getTime() / 1000)) {
				console.log("cleaning up.. ", id)
				await this.deleteState(id);
			}
		}));
	}
}
