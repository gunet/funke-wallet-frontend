import { ICredentialRepository } from '../interfaces/ICredentialRepository';
import { VerifiableCredentialFormat } from '../schemas/vc';

export class CredentialRepository implements ICredentialRepository {
    


    async store(format: VerifiableCredentialFormat, credential: object, vct?: string, doc_type?: string): Promise<void> {
        throw new Error("Method not implemented.")
    }
    async retrieveAll(): Promise<object[]> {
        throw new Error('Method not implemented.');
    }
}