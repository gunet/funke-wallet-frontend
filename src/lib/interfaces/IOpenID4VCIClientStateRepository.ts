import { OpenID4VCIClientState } from "../types/OpenID4VCIClientState";

export interface IOpenID4VCIClientStateRepository {
	store(id: string, s: OpenID4VCIClientState): Promise<void>;
	retrieve(id: string): Promise<OpenID4VCIClientState>;
	getAllStates(): Promise<OpenID4VCIClientState[]>;
	cleanupExpired(): Promise<void>;
}
