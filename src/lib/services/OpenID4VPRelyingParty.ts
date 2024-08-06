import { MDoc, parse } from "@auth0/mdl";
import { IOpenID4VPRelyingParty } from "../interfaces/IOpenID4VPRelyingParty";
import axios from "axios";
import { StorableCredential } from "../types/StorableCredential";
import { Verify } from "../utils/Verify";
import { HasherAlgorithm, HasherAndAlgorithm, SdJwt } from "@sd-jwt/core";
import { VerifiableCredentialFormat } from "../schemas/vc";
import { parseCredential } from "../../functions/parseCredential";
import { convertToJSONWithMaps, parseMsoMdocCredential } from "../mdl/mdl";
import { JSONPath } from "jsonpath-plus";
import { generateRandomIdentifier } from "../utils/generateRandomIdentifier";
import { base64url } from "jose";
import { OpenID4VPRelyingPartyState } from "../types/OpenID4VPRelyingPartyState";
import { OpenID4VPRelyingPartyStateRepository } from "./OpenID4VPRelyingPartyStateRepository";

export class OpenID4VPRelyingParty implements IOpenID4VPRelyingParty {


	constructor(
		private openID4VPRelyingPartyStateRepository: OpenID4VPRelyingPartyStateRepository,
		private getAllStoredVerifiableCredentials: () => Promise<{ verifiableCredentials: StorableCredential[] }>,
		private signJwtPresentationKeystoreFn: (nonce: string, audience: string, verifiableCredentials: any[]) => Promise<{ vpjwt: string }>,
		private generateDeviceResponseFn: (mdocCredential: MDoc, presentationDefinition: any, mdocGeneratedNonce: string, verifierGeneratedNonce: string, clientId: string, responseUri: string) => Promise<{ deviceResponseMDoc: MDoc }>
	) { }


	async handleAuthorizationRequest(url: string): Promise<{ conformantCredentialsMap: Map<string, any>, verifierDomainName: string; } | { err: "INSUFFICIENT_CREDENTIALS" }> {
		const authorizationRequest = new URL(url);
		const client_id = authorizationRequest.searchParams.get('client_id');
		const client_id_scheme = authorizationRequest.searchParams.get('client_id_scheme');
		const response_type = authorizationRequest.searchParams.get('response_type');
		const response_mode = authorizationRequest.searchParams.get('response_mode');
		const response_uri = authorizationRequest.searchParams.get('response_uri');
		const scope = authorizationRequest.searchParams.get('scope');
		const nonce = authorizationRequest.searchParams.get('nonce');
		const state = authorizationRequest.searchParams.get('state') as string;
		const presentation_definition_uri = authorizationRequest.searchParams.get('presentation_definition_uri');

		const [presentationDefinitionFetch, vcList] = await Promise.all([axios.get(presentation_definition_uri), this.getAllStoredVerifiableCredentials().then((res) => res.verifiableCredentials)]);

		const presentationDefinition = presentationDefinitionFetch.data;

		console.log("Stored definition = ", presentationDefinition)
		await this.openID4VPRelyingPartyStateRepository.store(new OpenID4VPRelyingPartyState(
			presentationDefinition,
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
		for (const descriptor of presentationDefinition.input_descriptors) {
			console.log("Descriptor :")
			console.dir(descriptor, { depth: null })
			const conformingVcList = []
			for (const vc of vcList) {
				console.log("VC = ", vc)
				try {
					if (vc.format == VerifiableCredentialFormat.SD_JWT_VC && VerifiableCredentialFormat.SD_JWT_VC in descriptor.format && Verify.verifyVcJwtWithDescriptor(descriptor, vc.credential)) {
						conformingVcList.push(vc.credentialIdentifier);
					}
					else if (vc.format == VerifiableCredentialFormat.MSO_MDOC && VerifiableCredentialFormat.MSO_MDOC in descriptor.format) {
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
							return { err: "INSUFFICIENT_CREDENTIALS" }; // there is at least one field missing from the requirements
						}

						conformingVcList.push(vc.credentialIdentifier);
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
				.map((field) => field.path)
				.reduce((accumulator, currentValue) => [...accumulator, ...currentValue])
				.map((field) => field.split('.')[field.split('.').length - 1]);
			mapping.set(descriptor.id, { credentials: [...conformingVcList], requestedFields: requestedFieldNames });
		}
		const verifierDomainName = new URL(response_uri).hostname;
		console.log("Verifier domain = ", verifierDomainName)
		if (mapping.size == 0) {
			console.log("Credentials don't satisfy any descriptor")
			throw new Error("Credentials don't satisfy any descriptor");
		}

		console.log("COnforming credentials ", mapping)
		return { conformantCredentialsMap: mapping, verifierDomainName: verifierDomainName };
	}


	async sendAuthorizationResponse(selectionMap: Map<string, string>): Promise<{ url?: string }> {
		const S = await this.openID4VPRelyingPartyStateRepository.retrieve();
		console.log("S = ", S)
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
			const result = {};

			paths.forEach((path) => {
				const keys = path.split(".").slice(1); // Splitting and removing the initial '$'
				let nestedObj = result;

				keys.forEach((key, index) => {
					if (index === keys.length - 1) {
						nestedObj[key] = true; // Setting the innermost key to true
					}
					else {
						nestedObj[key] = nestedObj[key] || {}; // Creating nested object if not exists
						nestedObj = nestedObj[key]; // Moving to the next nested object
					}
				});
			});
			return result;
		};


		const presentationDefinition = S.presentation_definition;
		console.log("DEF = ", presentationDefinition)
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
				).withHasher(hasherAndAlgorithm)
				console.log(sdJwt);
				const presentation = await sdJwt.present(presentationFrame);
				selectedVCs.push(presentation);
			}
			else if (vcEntity.format == VerifiableCredentialFormat.MSO_MDOC) {
				const submission = {
					"definition_id": presentationDefinition.id,
					"id": vcEntity.doctype,
					"descriptor_map": [
						{
							"id": vcEntity.doctype,
							"format": "mso_mdoc",
							"path": "$"
						}
					]
				};
				const parsed = await parseMsoMdocCredential(vcEntity.credential, vcEntity.doctype);
				const { deviceResponseMDoc } = await this.generateDeviceResponseFn(parsed, presentationDefinition, generateRandomIdentifier(8), nonce, client_id, response_uri);
				const formData = new URLSearchParams();
				formData.append('vp_token', base64url.encode(deviceResponseMDoc.encode()));
				formData.append('presentation_submission', JSON.stringify(submission));
				formData.append('state', state);

				const res = await axios.post(response_uri, formData.toString(), {
					maxRedirects: 0,
					headers: {
						'Content-Type': 'application/x-www-form-urlencoded',
					}
				});
				if (res.data.redirect_uri) {
					return { url: res.data.redirect_uri };
				}
			}
			else {
				selectedVCs.push(vcEntity.credential);
			}
		}

		const { vpjwt } = await this.signJwtPresentationKeystoreFn(nonce, response_uri, selectedVCs);
		const { conformingCredentials, presentationSubmission } = await Verify.getMatchesForPresentationDefinition(vpjwt, presentationDefinition);

		
		const formData = new URLSearchParams();
		formData.append('vp_token', vpjwt);
		formData.append('presentation_submission', JSON.stringify(presentationSubmission));
		formData.append('state', S.state);

		const res = await axios.post(response_uri, formData.toString(), {
			maxRedirects: 0,
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
			}
		});
		if (res.data.redirect_uri) {
			return { url: res.data.redirect_uri };
		}
	}
}
