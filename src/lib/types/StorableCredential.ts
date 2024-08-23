import { VerifiableCredentialFormat } from "../schemas/vc"

export type StorableCredential = {
	credentialIdentifier: string;
	format: VerifiableCredentialFormat.MSO_MDOC;
	credential: string;
	doctype: string;
} | {
	credentialIdentifier: string;
	format: VerifiableCredentialFormat.SD_JWT_VC;
	credential: string;
	vct: string;
} | {
	credentialIdentifier: string;
	format: VerifiableCredentialFormat.VC_JWT;
	credential: string;
}
