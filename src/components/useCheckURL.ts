import { useEffect, useState, Dispatch, SetStateAction, useContext } from 'react';
import { useApi } from '../api';
import { useLocalStorageKeystore } from '../services/LocalStorageKeystore';
import { useTranslation } from 'react-i18next';
import { useCommunicationProtocols } from './useCommunicationProtocols';
import SessionContext from '../context/SessionContext';

export enum HandleOutboundRequestError {
	INSUFFICIENT_CREDENTIALS = "INSUFFICIENT_CREDENTIALS",
}

export enum SendResponseError {
	SEND_RESPONSE_ERROR = "SEND_RESPONSE_ERROR",
}

const isMobile = window.innerWidth <= 480;
const eIDClientURL = isMobile ? process.env.REACT_APP_OPENID4VCI_EID_CLIENT_URL.replace('http', 'eid') : process.env.REACT_APP_OPENID4VCI_EID_CLIENT_URL;


function useCheckURL(urlToCheck: string): {
	showSelectCredentialsPopup: boolean,
	setShowSelectCredentialsPopup: Dispatch<SetStateAction<boolean>>,
	setSelectionMap: Dispatch<SetStateAction<{ [x: string]: string } | null>>,
	conformantCredentialsMap: any,
	showPinInputPopup: boolean,
	setShowPinInputPopup: Dispatch<SetStateAction<boolean>>,
	verifierDomainName: string,
	showMessagePopup: boolean;
	setMessagePopup: Dispatch<SetStateAction<boolean>>;
	textMessagePopup: { title: string, description: string };
	typeMessagePopup: string;
} {
	const api = useApi();
	const { openID4VCIClients, httpProxy, openID4VPRelyingParty } = useCommunicationProtocols();
	const { isLoggedIn } = useContext(SessionContext);
	const [showSelectCredentialsPopup, setShowSelectCredentialsPopup] = useState<boolean>(false);
	const [showPinInputPopup, setShowPinInputPopup] = useState<boolean>(false);
	const [selectionMap, setSelectionMap] = useState<{ [x: string]: string } | null>(null);
	const [conformantCredentialsMap, setConformantCredentialsMap] = useState(null);
	const [verifierDomainName, setVerifierDomainName] = useState("");
	const [showMessagePopup, setMessagePopup] = useState<boolean>(false);
	const [textMessagePopup, setTextMessagePopup] = useState<{ title: string, description: string }>({ title: "", description: "" });
	const [typeMessagePopup, setTypeMessagePopup] = useState<string>("");
	const keystore = useLocalStorageKeystore();
	const { t } = useTranslation();

	useEffect(() => {

		async function communicationHandler(url: string): Promise<boolean> {
			try {
				const wwwallet_camera_was_used = new URL(url).searchParams.get('wwwallet_camera_was_used');

				const res = await api.post('/communication/handle', { url, camera_was_used: (wwwallet_camera_was_used != null && wwwallet_camera_was_used === 'true') });
				const { redirect_to, conformantCredentialsMap, verifierDomainName, preauth, ask_for_pin, error } = res.data;
				if (error && error === HandleOutboundRequestError.INSUFFICIENT_CREDENTIALS) {
					console.error(`${HandleOutboundRequestError.INSUFFICIENT_CREDENTIALS}`);
					setTextMessagePopup({ title: `${t('messagePopup.insufficientCredentials.title')}`, description: `${t('messagePopup.insufficientCredentials.description')}` });
					setTypeMessagePopup('error');
					setMessagePopup(true);
					return false;
				}

				if (preauth && preauth === true) {
					if (ask_for_pin) {
						setShowPinInputPopup(true);
						return true;
					}
					else {
						await api.post('/communication/handle', { user_pin: "" });
						return true;
					}
				}

				if (redirect_to) {
					window.location.href = redirect_to;
					return true;
				} else if (conformantCredentialsMap) {
					console.log('need action');
					setVerifierDomainName(verifierDomainName);
					setConformantCredentialsMap(conformantCredentialsMap);
					setShowSelectCredentialsPopup(true);
					console.log("called setShowSelectCredentialsPopup")
					return true;
				}
				else {
					return false;
				}
			}
			catch (err) {
				console.log("Failed to handle");
				return false;
			}
		}

		const u = new URL(urlToCheck);
		if (u.protocol == 'openid-credential-offer' || u.searchParams.get('credential_offer')) {
			for (const credentialIssuerIdentifier of Object.keys(openID4VCIClients)) {
				console.log("Url to check = ", urlToCheck)
				openID4VCIClients[credentialIssuerIdentifier].handleCredentialOffer(u.toString())
					.then(({ credentialIssuer, selectedCredentialConfigurationSupported }) => {
						const userHandleB64u = keystore.getUserHandleB64u();
						if (userHandleB64u == null) {
							throw new Error("user handle is null")
						}
						return openID4VCIClients[credentialIssuerIdentifier].generateAuthorizationRequest(selectedCredentialConfigurationSupported, userHandleB64u);
					})
					.then(({ url, client_id, request_uri }) => {
					console.log("Request uri = ", request_uri)
					const urlObj = new URL(url);
					// Construct the base URL
					const baseUrl = `${urlObj.protocol}//${urlObj.hostname}${urlObj.pathname}`;

					// Parameters
					// Encode parameters
					const encodedClientId = encodeURIComponent(client_id);
					const encodedRequestUri = encodeURIComponent(request_uri);
					const tcTokenURL = `${baseUrl}?client_id=${encodedClientId}&request_uri=${encodedRequestUri}`;

					const newLoc = `${eIDClientURL}?tcTokenURL=${encodeURIComponent(tcTokenURL)}`

					console.log("new loc = ", newLoc)
					window.location.href = newLoc;
				})
				.catch((err) => console.error(err));
			}
		}

		if (u.searchParams.get('code')) {
			for (const credentialIssuerIdentifier of Object.keys(openID4VCIClients)) {
				console.log("Url to check = ", urlToCheck)
				openID4VCIClients[credentialIssuerIdentifier].handleAuthorizationResponse(urlToCheck)
					.catch(err => {
						console.log("Error during the handling of authorization response")
						console.error(err)
					});
			}
		}
		openID4VPRelyingParty.handleAuthorizationRequest(urlToCheck).then((result) => {
			if ('err' in result) {
				if (result.err == "INSUFFICIENT_CREDENTIALS") {
					setTextMessagePopup({ title: `${t('messagePopup.insufficientCredentials.title')}`, description: `${t('messagePopup.insufficientCredentials.description')}` });
					setTypeMessagePopup('error');
					setMessagePopup(true);
				}
				return;
			}
			const { conformantCredentialsMap, verifierDomainName } = result;
			const jsonedMap = Object.fromEntries(conformantCredentialsMap);
			setVerifierDomainName(verifierDomainName);
			setConformantCredentialsMap(jsonedMap);
			setShowSelectCredentialsPopup(true);
		}).catch(err => {
			console.log("Failed to handle authorization req");
			console.error(err)
		})

	}, [api, keystore, t, urlToCheck, isLoggedIn, openID4VCIClients]);

	useEffect(() => {
		if (selectionMap) {
			openID4VPRelyingParty.sendAuthorizationResponse(new Map(Object.entries(selectionMap))).then(({ url }) => {
				if (url) {
					window.location.href = url;
				}
			}).catch((err) => console.error(err));
			// api.post("/communication/handle",
			// 	{ verifiable_credentials_map: selectionMap },
			// ).then(success => {
			// 	console.log(success);
			// 	const { redirect_to, error } = success.data;

			// 	if (error && error === SendResponseError.SEND_RESPONSE_ERROR) {
			// 		setTextMessagePopup({ title: `${t('messagePopup.sendResponseError.title')}`, description: `${t('messagePopup.sendResponseError.description')}` });
			// 		setTypeMessagePopup('error');
			// 		setMessagePopup(true);
			// 		return;
			// 	}
			// 	if (redirect_to) {
			// 		window.location.href = redirect_to; // Navigate to the redirect URL
			// 	}
			// 	else {
			// 		setTextMessagePopup({ title: `${t('messagePopup.sendResponseSuccess.title')}`, description: `${t('messagePopup.sendResponseSuccess.description')}` });
			// 		setTypeMessagePopup('success');
			// 		setMessagePopup(true);
			// 		return;
			// 	}
			// }).catch(err => {
			// 	console.error("Error");
			// 	console.error(err);
			// });
		}
	}, [api, keystore, selectionMap, t]);

	return { showSelectCredentialsPopup, setShowSelectCredentialsPopup, setSelectionMap, conformantCredentialsMap, showPinInputPopup, setShowPinInputPopup, verifierDomainName, showMessagePopup, setMessagePopup, textMessagePopup, typeMessagePopup };
}

export default useCheckURL;
