import { MDoc } from "@auth0/mdl";
import { IOpenID4VPRelyingParty } from "../interfaces/IOpenID4VPRelyingParty";
import { StorableCredential } from "../types/StorableCredential";
import { Verify } from "../utils/Verify";
import { HasherAlgorithm, HasherAndAlgorithm, SdJwt } from "@sd-jwt/core";
import { VerifiableCredentialFormat } from "../schemas/vc";
import { parseMsoMdocCredential } from "../mdl/mdl";
import { JSONPath } from "jsonpath-plus";
import { generateRandomIdentifier } from "../utils/generateRandomIdentifier";
import { base64url } from "jose";
import { OpenID4VPRelyingPartyState } from "../types/OpenID4VPRelyingPartyState";
import { OpenID4VPRelyingPartyStateRepository } from "./OpenID4VPRelyingPartyStateRepository";
import { IHttpProxy } from "../interfaces/IHttpProxy";
import { parseCredential } from "../../functions/parseCredential";

export class OpenID4VPRelyingParty implements IOpenID4VPRelyingParty {


	constructor(
		private openID4VPRelyingPartyStateRepository: OpenID4VPRelyingPartyStateRepository,
		private httpProxy: IHttpProxy,
		private getAllStoredVerifiableCredentials: () => Promise<{ verifiableCredentials: StorableCredential[] }>,
		private signJwtPresentationKeystoreFn: (nonce: string, audience: string, verifiableCredentials: any[]) => Promise<{ vpjwt: string }>,
		private generateDeviceResponseFn: (mdocCredential: MDoc, presentationDefinition: any, mdocGeneratedNonce: string, verifierGeneratedNonce: string, clientId: string, responseUri: string) => Promise<{ deviceResponseMDoc: MDoc }>,
		private storeVerifiablePresentation: (presentation: string, format: string, identifiersOfIncludedCredentials: string[], presentationSubmission: any, audience: string) => Promise<void>
	) { }


	async handleAuthorizationRequest(url: string): Promise<{ conformantCredentialsMap: Map<string, any>, verifierDomainName: string; } | { err: "INSUFFICIENT_CREDENTIALS" | "MISSING_PRESENTATION_DEFINITION_URI" | "ONLY_ONE_INPUT_DESCRIPTOR_IS_SUPPORTED" }> {
		const authorizationRequest = new URL(url);
		let client_id = authorizationRequest.searchParams.get('client_id');
		let client_id_scheme = authorizationRequest.searchParams.get('client_id_scheme');
		let response_type = authorizationRequest.searchParams.get('response_type');
		let response_mode = authorizationRequest.searchParams.get('response_mode');
		let response_uri = authorizationRequest.searchParams.get('response_uri');
		let scope = authorizationRequest.searchParams.get('scope');
		let nonce = authorizationRequest.searchParams.get('nonce');
		let state = authorizationRequest.searchParams.get('state') as string;
		let presentation_definition = authorizationRequest.searchParams.get('presentation_definition') ? JSON.parse(authorizationRequest.searchParams.get('presentation_definition')) : null;
		let presentation_definition_uri = authorizationRequest.searchParams.get('presentation_definition_uri');

		let client_metadata = {};

		if (presentation_definition_uri) {
			const presentationDefinitionFetch = await this.httpProxy.get(presentation_definition_uri, {});
			presentation_definition = presentationDefinitionFetch.data;
		}

		const request_uri = authorizationRequest.searchParams.get('request_uri');


		if (request_uri) {
			const requestUriResponse = await this.httpProxy.get(request_uri, {});
			const requestObject = requestUriResponse.data; // jwt
			const [header, payload, sig] = requestObject.split('.');
			const p = JSON.parse(new TextDecoder().decode(base64url.decode(payload)));
			client_id = p.client_id;
			client_id_scheme = p.client_id_scheme;
			response_type = p.response_type;
			presentation_definition = p.presentation_definition;
			response_mode = p.response_mode;
			response_uri = p.response_uri ?? p.redirect_uri;
			state = p.state;
			nonce = p.nonce;
			client_metadata = p.client_metadata;
			if (!response_uri.startsWith("http")) {
				response_uri = `https://${response_uri}`;
			}
		}

		const vcList = await this.getAllStoredVerifiableCredentials().then((res) => res.verifiableCredentials);

		if (presentation_definition.input_descriptors.length > 1) {
			return { err: "ONLY_ONE_INPUT_DESCRIPTOR_IS_SUPPORTED" };

		}

		await this.openID4VPRelyingPartyStateRepository.store(new OpenID4VPRelyingPartyState(
			presentation_definition,
			nonce,
			response_uri,
			client_id,
			state
		));
		// localStorage.setItem("presentationDefinition", JSON.stringify(presentationDefinition)); // will change
		// localStorage.setItem("nonce", nonce);
		// localStorage.setItem("response_uri", response_uri);
		// localStorage.setItem("client_id", client_id);
		// localStorage.setItem("state", state);

		const mapping = new Map<string, { credentials: string[], requestedFields: string[] }>();
		for (const descriptor of presentation_definition.input_descriptors) {
			const conformingVcList = []
			for (const vc of vcList) {
				try {

					if (vc.format == VerifiableCredentialFormat.SD_JWT_VC && (descriptor.format == undefined || VerifiableCredentialFormat.SD_JWT_VC in descriptor.format)) {
						const parsed = await parseCredential({ credential: vc.credential, format: vc.format, vct: vc.vct, credentialIdentifier: "random" });
						if (Verify.verifyVcJwtWithDescriptor(descriptor, parsed)) {
							conformingVcList.push(vc.credentialIdentifier);
							continue;
						}
					}

					if (vc.format == VerifiableCredentialFormat.MSO_MDOC && (descriptor.format == undefined || VerifiableCredentialFormat.MSO_MDOC in descriptor.format)) {
						console.log("Credential to be mdoc parsed = ", vc.credential)
						const parsed = await parseMsoMdocCredential(vc.credential, vc.doctype);
						const ns = parsed.documents[0].getIssuerNameSpace(vc.doctype);
						const json = {};
						json[vc.doctype] = ns;

						const fieldsWithValue = descriptor.constraints.fields.map((field) => {
							const values = field.path.map((possiblePath) => JSONPath({ path: possiblePath, json: json })[0]);
							const val = values.filter((v) => v != undefined || v != null)[0]; // get first value that is not undefined
							return { field, val };
						});
						console.log("Fields with value = ", fieldsWithValue)

						if (fieldsWithValue.map((fwv) => fwv.val).includes(undefined)) {
							continue; // there is at least one field missing from the requirements
						}

						conformingVcList.push(vc.credentialIdentifier);
						continue;
					}
				}
				catch (err) {
					console.error("Failed to match a descriptor")
					console.error(err)
				}

			}
			if (conformingVcList.length == 0) {
				return { err: "INSUFFICIENT_CREDENTIALS" };
			}
			const requestedFieldNames = descriptor.constraints.fields
				.map((field) => {
					if (field.name) {
						return field.name;
					}
					return field.path[0];
				})
			mapping.set(descriptor.id, { credentials: [...conformingVcList], requestedFields: requestedFieldNames });
		}
		const verifierDomainName = client_id.includes("http") ? new URL(client_id).hostname : client_id;
		if (mapping.size == 0) {
			console.log("Credentials don't satisfy any descriptor")
			throw new Error("Credentials don't satisfy any descriptor");
		}

		return { conformantCredentialsMap: mapping, verifierDomainName: verifierDomainName };
	}


	async sendAuthorizationResponse(selectionMap: Map<string, string>): Promise<{ url?: string }> {
		const S = await this.openID4VPRelyingPartyStateRepository.retrieve();
		async function hashSHA256(input) {
			// Step 1: Encode the input string as a Uint8Array
			const encoder = new TextEncoder();
			const data = encoder.encode(input);

			// Step 2: Hash the data using SHA-256
			const hashBuffer = await crypto.subtle.digest('SHA-256', data);
			return new Uint8Array(hashBuffer);
		}

		const hasherAndAlgorithm: HasherAndAlgorithm = {
			hasher: async (input: string) => hashSHA256(input),
			algorithm: HasherAlgorithm.Sha256
		}

		/**
		*
		* @param paths example: [ '$.credentialSubject.image', '$.credentialSubject.grade', '$.credentialSubject.val.x' ]
		* @returns example: { credentialSubject: { image: true, grade: true, val: { x: true } } }
		*/
		const generatePresentationFrameForPaths = (paths) => {
			let result = {};

			paths.forEach((path: string) => {
				if (path.includes("[")) {
					// Use the matchAll method to get all matches
					let matches = [...path.matchAll(/\['(.*?)'\]/g)];

					// Initialize an empty object to build the result
					let current = result;

					// Iterate over each match and build the nested object
					for (let i = 0; i < matches.length; i++) {
						let key = matches[i][1];

						// If this is the last key, set its value to true
						if (i === matches.length - 1) {
							current[key] = true;
						} else {
							// Otherwise, create a new nested object if it doesn't exist
							current[key] = current[key] || {};
							current = current[key];
						}
					}
				}
				else {
					let keys = path.replace(/^\$\./, '').split('.');
					// Initialize an empty object to build the result
					let current = result;

					// Iterate over each key and build the nested object
					for (let i = 0; i < keys.length; i++) {
						let key = keys[i];

						// If this is the last key, set its value to true
						if (i === keys.length - 1) {
							current[key] = true;
						} else {
							// Otherwise, create a new nested object if it doesn't exist
							current[key] = current[key] || {};
							current = current[key];
						}
					}
				}
			});
			return result;
		};


		const presentationDefinition = S.presentation_definition;
		const response_uri = S.response_uri;
		const client_id = S.client_id;
		const nonce = S.nonce;
		const state = S.state;

		let { verifiableCredentials } = await this.getAllStoredVerifiableCredentials();
		const allSelectedCredentialIdentifiers = Array.from(selectionMap.values());
		const filteredVCEntities = verifiableCredentials
			.filter((vc) =>
				allSelectedCredentialIdentifiers.includes(vc.credentialIdentifier),
			);

		let selectedVCs = [];
		let generatedVPs = [];
		let originalVCs = [];
		const descriptorMap = [];
		let i = 0;
		for (const [descriptor_id, credentialIdentifier] of selectionMap) {
			const vcEntity = filteredVCEntities.filter((vc) => vc.credentialIdentifier == credentialIdentifier)[0];
			if (vcEntity.format == VerifiableCredentialFormat.SD_JWT_VC) {
				const descriptor = presentationDefinition.input_descriptors.filter((desc) => desc.id == descriptor_id)[0];
				const allPaths = descriptor.constraints.fields
					.map((field) => field.path)
					.reduce((accumulator, currentValue) => [...accumulator, ...currentValue]);
				let presentationFrame = generatePresentationFrameForPaths(allPaths);
				const sdJwt = SdJwt.fromCompact<Record<string, unknown>, any>(
					vcEntity.credential
				).withHasher(hasherAndAlgorithm);
				const presentation = await sdJwt.present(presentationFrame);
				const { vpjwt } = await this.signJwtPresentationKeystoreFn(nonce, client_id, [presentation]);
				selectedVCs.push(presentation);
				generatedVPs.push(vpjwt);
				descriptorMap.push({
					id: descriptor_id,
					format: VerifiableCredentialFormat.SD_JWT_VC,
					path: `$`
				});
				i++;
				originalVCs.push(vcEntity);
			}
			else if (vcEntity.format == VerifiableCredentialFormat.MSO_MDOC) {
				const parsed = await parseMsoMdocCredential(vcEntity.credential, vcEntity.doctype);
				const { deviceResponseMDoc } = await this.generateDeviceResponseFn(parsed, presentationDefinition, generateRandomIdentifier(8), nonce, client_id, response_uri);
				const encodedDeviceResponse = base64url.encode(deviceResponseMDoc.encode());

				selectedVCs.push(encodedDeviceResponse);
				generatedVPs.push(encodedDeviceResponse);
				descriptorMap.push({
					id: descriptor_id,
					format: VerifiableCredentialFormat.MSO_MDOC,
					path: `$`
				});
				i++;
				originalVCs.push(vcEntity);

			}
		}

		const presentationSubmission = {
			id: "123123",
			definition_id: S.presentation_definition.id,
			descriptor_map: descriptorMap,
		};

		const formData = new URLSearchParams();
		formData.append('vp_token', generatedVPs[0]);
		formData.append('presentation_submission', JSON.stringify(presentationSubmission));
		formData.append('state', S.state);

		const credentialIdentifiers = originalVCs.map((vc) => vc.credentialIdentifier);

		await this.storeVerifiablePresentation(generatedVPs[0], presentationSubmission.descriptor_map[0].format, credentialIdentifiers, presentationSubmission, client_id);

		const res = await this.httpProxy.post(response_uri, formData.toString(), {
			'Content-Type': 'application/x-www-form-urlencoded',
		});

		console.log("Direct post response = ", res);

		if (res.data.redirect_uri) {
			return { url: res.data.redirect_uri };
		}
	}
}
