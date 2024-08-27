import { MDoc, parse } from "@auth0/mdl";
import * as cbor from 'cbor-x';
import * as jose from 'jose';
import { binaryToPem, fromDerToPKIJSCertificate, importCert, validateChain } from "../utils/pki";


export const verifyMdocWithAllCerts = async (mdoc: MDoc) => {
	const issuerAuth = mdoc.documents[0].issuerSigned.issuerAuth;
	// @ts-ignore
	const chainDER = issuerAuth.unprotectedHeaders.get('33') as Array<Uint8Array>;
	const chain = chainDER.map((derCert) => fromDerToPKIJSCertificate(derCert));

	const isValidChain = await validateChain(chain);
	if (!isValidChain) {
		return false;
	}

	try {
		const pem = binaryToPem(chainDER[0]);
		const importedCert = await importCert(pem);
		const result = await issuerAuth.verify(importedCert)
		return result;
	}
	catch (err) {
		console.log("MDOC verification failed")
		console.error(err)
		return false;
	}
}

export const parseMsoMdocCredential = async (mso_mdoc_cred: string, docType: string): Promise<MDoc> => {

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

export const parseMsoMdocDeviceResponse = async (mso_mdoc_device_response: string): Promise<MDoc> => {
	const dec = jose.base64url.decode(mso_mdoc_device_response);
	return parse(dec);
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
