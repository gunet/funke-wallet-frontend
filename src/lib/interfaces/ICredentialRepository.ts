import { VerifiableCredentialFormat } from "../schemas/vc";

export interface ICredentialRepository {
	store(format: VerifiableCredentialFormat, credential: object, vct?: string, doc_type?: string): Promise<void>;
	retrieveAll(): Promise<object[]>;
}