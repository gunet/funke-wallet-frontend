
export interface ICredentialRepository {
	store(credential: object): Promise<void>;
	retrieve(): Promise<object>;
}