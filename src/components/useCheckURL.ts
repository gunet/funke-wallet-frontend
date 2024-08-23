import { useEffect, useState, Dispatch, SetStateAction, useContext } from 'react';
import { useApi } from '../api';
import { useTranslation } from 'react-i18next';
import { useCommunicationProtocols } from './useCommunicationProtocols';
import SessionContext from '../context/SessionContext';
import { BackgroundTasksContext } from '../context/BackgroundTasksContext';

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
	const { isLoggedIn, keystore } = useContext(SessionContext);
	const { protocols } = useCommunicationProtocols();
	const { addLoader, removeLoader } = useContext(BackgroundTasksContext);

	const [showSelectCredentialsPopup, setShowSelectCredentialsPopup] = useState<boolean>(false);
	const [showPinInputPopup, setShowPinInputPopup] = useState<boolean>(false);
	const [selectionMap, setSelectionMap] = useState<{ [x: string]: string } | null>(null);
	const [conformantCredentialsMap, setConformantCredentialsMap] = useState(null);
	const [verifierDomainName, setVerifierDomainName] = useState("");
	const [showMessagePopup, setMessagePopup] = useState<boolean>(false);
	const [textMessagePopup, setTextMessagePopup] = useState<{ title: string, description: string }>({ title: "", description: "" });
	const [typeMessagePopup, setTypeMessagePopup] = useState<string>("");
	const { t } = useTranslation();


	async function handle(urlToCheck: string) {
		const u = new URL(urlToCheck);
		if ((u.protocol == 'openid-credential-offer' || u.searchParams.get('credential_offer'))) {
			for (const credentialIssuerIdentifier of Object.keys(protocols.openID4VCIClients)) {
				console.log("Url to check = ", urlToCheck)
				await protocols.openID4VCIClients[credentialIssuerIdentifier].handleCredentialOffer(u.toString())
					.then(({ credentialIssuer, selectedCredentialConfigurationSupported }) => {
						const userHandleB64u = keystore.getUserHandleB64u();
						if (userHandleB64u == null) {
							throw new Error("user handle is null")
						}
						return protocols.openID4VCIClients[credentialIssuerIdentifier].generateAuthorizationRequest(selectedCredentialConfigurationSupported, userHandleB64u);
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
		else if (u.searchParams.get('code')) {
			for (const credentialIssuerIdentifier of Object.keys(protocols.openID4VCIClients)) {
				console.log("Url to check = ", urlToCheck)
				addLoader();
				await protocols.openID4VCIClients[credentialIssuerIdentifier].handleAuthorizationResponse(urlToCheck)
					.then(() => {
						window.history.replaceState({}, '', `${window.location.pathname}`);
						removeLoader();
					})
					.catch(err => {
						console.log("Error during the handling of authorization response")
						window.history.replaceState({}, '', `${window.location.pathname}`);
						console.error(err)
						removeLoader();
					});
			}
		}
		else {
			await protocols.openID4VPRelyingParty.handleAuthorizationRequest(urlToCheck).then((result) => {
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
				window.history.replaceState({}, '', `${window.location.pathname}`);
				setVerifierDomainName(verifierDomainName);
				setConformantCredentialsMap(jsonedMap);
				setShowSelectCredentialsPopup(true);
			}).catch(err => {
				console.log("Failed to handle authorization req");
				console.error(err)
			})
		}

		const urlParams = new URLSearchParams(window.location.search);
		const state = urlParams.get('state');
		const error = urlParams.get('error');
		if (urlToCheck && isLoggedIn && state && error) {
			window.history.replaceState({}, '', `${window.location.pathname}`);
			const errorDescription = urlParams.get('error_description');
			setTextMessagePopup({ title: error, description: errorDescription });
			setTypeMessagePopup('error');
			setMessagePopup(true);
		}
	}

	useEffect(() => {
		if (!isLoggedIn || !protocols || !urlToCheck || !keystore || !api || !t) {
			return;
		}
		console.log("URL to check = ", urlToCheck)
		handle(urlToCheck);
	}, [api, keystore, t, urlToCheck, isLoggedIn, protocols]);

	useEffect(() => {
		if (selectionMap) {
			protocols.openID4VPRelyingParty.sendAuthorizationResponse(new Map(Object.entries(selectionMap))).then(({ url }) => {
				if (url) {
					window.location.href = url;
				}
			}).catch((err) => console.error(err));
		}
	}, [api, keystore, selectionMap, t, protocols]);

	return { showSelectCredentialsPopup, setShowSelectCredentialsPopup, setSelectionMap, conformantCredentialsMap, showPinInputPopup, setShowPinInputPopup, verifierDomainName, showMessagePopup, setMessagePopup, textMessagePopup, typeMessagePopup };
}

export default useCheckURL;
