import { StorableCredential } from "../lib/types/StorableCredential";
import { parseCredential } from "./parseCredential";


export const extractCredentialFriendlyName = async (credential: StorableCredential): Promise<string | undefined> => {
	const parsedCredential = await parseCredential(credential) as any;
	return (parsedCredential.name ?? parsedCredential.id) ?? "Credential";
}
