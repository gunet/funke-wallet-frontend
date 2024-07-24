import { VerifiableCredentialFormat } from "../schemas/vc"

export type StorableCredential = {
    format: VerifiableCredentialFormat.MSO_MDOC;
    credential: string;
    doctype: string;
} | {
    format: VerifiableCredentialFormat.SD_JWT_VC;
    credential: string;
    vct: string;
} | {
    format: VerifiableCredentialFormat.VC_JWT;
    credential: string;
}