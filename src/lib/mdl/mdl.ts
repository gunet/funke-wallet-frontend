import { MDoc, parse } from "@auth0/mdl";
import * as cbor from 'cbor-x';
import * as jose from 'jose';

const trustedCerts = process.env.REACT_APP_TRUST_ANCHOR_CERTS_JSON_B64U ? JSON.parse(new TextDecoder().decode(jose.base64url.decode(process.env.REACT_APP_TRUST_ANCHOR_CERTS_JSON_B64U))) : [];


const importCert = async (cert) => {
	// convert issuer cert to KeyLike
	const issuerCertJose = await jose.importX509(cert, 'ES256', { extractable: true });
	// convert issuer cert from KeyLike to JWK
	const issuerCertJwk = await jose.exportJWK(issuerCertJose)
	// import issuer cert from JWK to CryptoKey
	const importedCert = await crypto.subtle.importKey('jwk',
		issuerCertJwk,
		{ name: 'ECDSA', namedCurve: 'P-256' },
		true,
		['verify']
	);
	return importedCert;
}


export const verifyMdocWithAllCerts = async (mdoc: MDoc) => {
	const issuerAuth = mdoc.documents[0].issuerSigned.issuerAuth;
	const results = await Promise.all(trustedCerts.map(async (cert: string) => {
		cert = cert.trim();
		try {
			return issuerAuth.verify(await importCert(cert));
		}
		catch (err) {
			console.error(err)
			return false;
		}
	})) as boolean[];

	const verifiedWithAtleastOneCert = results.find((v) => v == true);
	return verifiedWithAtleastOneCert == true;
}

export const parseMsoMdocCredential = async (mso_mdoc_cred: string, docType: string): Promise<any> => {

	const credentialBytes = jose.base64url.decode(mso_mdoc_cred);
	const issuerSigned = await cbor.decode(credentialBytes);
	const m = {
		version: '1.0',
		documents: [new Map([
			['docType', docType],
			['issuerSigned', issuerSigned]
		])],
		status: 0
	}
	const encoded = cbor.encode(m) as Uint8Array;
	return parse(encoded);
}

export const convertToJSONWithMaps = (obj) => {
	return JSON.parse(JSON.stringify(obj, (key, value) => {
		if (value instanceof Map) {
			const obj = {};
			for (let [k, v] of value) {
				obj[k] = v;
			}
			return obj;
		}
		return value;
	}));
}
