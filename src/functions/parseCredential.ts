import parseJwt from './ParseJwt';
import {
	HasherAlgorithm,
	HasherAndAlgorithm,
	SdJwt,
	SignatureAndEncryptionAlgorithm,
	Verifier,
} from '@sd-jwt/core'
import { VerifiableCredentialFormat } from '../lib/schemas/vc';
import { StorableCredential } from '../lib/types/StorableCredential';
import { convertToJSONWithMaps, parseMsoMdocCredential, verifyMdocWithAllCerts } from '../lib/mdl/mdl';
import { verifySdJwtBasedOnTrustAnchors } from '../lib/sd-jwt/sd-jwt';

export enum CredentialFormat {
	VC_SD_JWT = "vc+sd-jwt",
	JWT_VC_JSON = "jwt_vc_json"
}

const encoder = new TextEncoder();

// Encoding the string into a Uint8Array
const hasherAndAlgorithm: HasherAndAlgorithm = {
	hasher: (input: string) => {
		return crypto.subtle.digest('SHA-256', encoder.encode(input)).then((v) => new Uint8Array(v));
	},
	algorithm: HasherAlgorithm.Sha256
}

export const parseCredential = async (credential: StorableCredential): Promise<object> => {

	const verifierCb: Verifier = async ({ header, message, signature }) => {
		if (header.alg && header.alg !== SignatureAndEncryptionAlgorithm.ES256) {
			throw new Error('only ES256 is supported');
		}
		if (header['x5c'] && header['x5c'][0]) {
			return verifySdJwtBasedOnTrustAnchors(credential.credential)
		}
	}

	if (credential.format == VerifiableCredentialFormat.SD_JWT_VC) { // is SD-JWT
		const verificationResult = await SdJwt.fromCompact<Record<string, unknown>, any>(credential.credential)
			.withHasher(hasherAndAlgorithm)
			.verify(verifierCb);
		console.log("SD Verification result = ", verificationResult)
		return await SdJwt.fromCompact<Record<string, unknown>, any>(credential.credential)
			.withHasher(hasherAndAlgorithm)
			.getPrettyClaims()
			.then((payload) => payload.vc ? payload.vc : payload)
	}

	if (credential.format == VerifiableCredentialFormat.MSO_MDOC) {
		const parsed = await parseMsoMdocCredential(credential.credential, credential.doctype);
		const result = await verifyMdocWithAllCerts(parsed);
		console.log("MDOC verification result = ", result)
		const ns = parsed.documents[0].getIssuerNameSpace(credential.doctype);
		return convertToJSONWithMaps(ns);
	}

	if (credential.format == VerifiableCredentialFormat.VC_JWT) { // is plain JWT
		return parseJwt(credential.credential)
			.then((payload) => payload.vc ? payload.vc : payload);
	}

}
