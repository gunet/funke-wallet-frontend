import React, { useState, useEffect, useContext } from 'react';
import { useTranslation } from 'react-i18next';

import QRCodeScanner from '../../components/QRCodeScanner/QRCodeScanner';
import RedirectPopup from '../../components/Popups/RedirectPopup';
import QRButton from '../../components/Buttons/QRButton';
import { useApi } from '../../api';
import OnlineStatusContext from '../../context/OnlineStatusContext';
import { H1 } from '../../components/Heading';
import { BackgroundTasksContext } from '../../context/BackgroundTasksContext';
import { base64url } from 'jose';
import { useLocalStorageKeystore } from '../../services/LocalStorageKeystore';
import CommunicationProtocolsContext from '../../context/CommunicationProtocolsContext';

function highlightBestSequence(issuer, search) {
	if (typeof issuer !== 'string' || typeof search !== 'string') {
		return issuer;
	}

	const searchRegex = new RegExp(search, 'gi');
	const highlighted = issuer.replace(searchRegex, '<span class="font-bold text-primary dark:text-primary-light">$&</span>');

	return highlighted;
}


const trustedCredentialIssuers = JSON.parse(new TextDecoder().decode(base64url.decode(process.env.REACT_APP_REGISTERED_CREDENTIAL_ISSUERS_JSON_B64U)));
const isMobile = window.innerWidth <= 480;
const eIDClientURL = isMobile ? process.env.REACT_APP_OPENID4VCI_EID_CLIENT_URL.replace('http', 'eid') : process.env.REACT_APP_OPENID4VCI_EID_CLIENT_URL;

const Issuers = () => {
	const { isOnline } = useContext(OnlineStatusContext);
	const { addLoader, removeLoader } = useContext(BackgroundTasksContext);
	const api = useApi(isOnline);
	const { protocols } = useContext(CommunicationProtocolsContext);

	const [searchQuery, setSearchQuery] = useState('');
	const [issuers, setIssuers] = useState([]);
	const [filteredIssuers, setFilteredIssuers] = useState([]);
	const [showRedirectPopup, setShowRedirectPopup] = useState(false);
	const [selectedIssuer, setSelectedIssuer] = useState(null);
	const [loading, setLoading] = useState(false);
	const [isSmallScreen, setIsSmallScreen] = useState(window.innerWidth < 768);

	const [credentialIssuers, setCredentialIssuers] = useState([]);
	const [availableCredentialConfigurations, setAvailableCredentialConfigurations] = useState(null);

	const keystore = useLocalStorageKeystore();
	const { t } = useTranslation();

	async function getAllCredentialIssuerMetadata() {
		return Promise.all(trustedCredentialIssuers.map(async (credentialIssuer) => {
			const { metadata } = await protocols.openID4VCIHelper.getCredentialIssuerMetadata(credentialIssuer.credential_issuer_identifier);
			return {
				credentialIssuerIdentifier: credentialIssuer.credential_issuer_identifier,
				selectedDisplay: metadata.display.filter((display) => display.locale === 'en-US')[0]
			}
		}));
	}

	useEffect(() => {
		const handleResize = () => {
			setIsSmallScreen(window.innerWidth < 768);
		};

		window.addEventListener('resize', handleResize);
		addLoader();
		getAllCredentialIssuerMetadata().then((issuers) => {
			setCredentialIssuers(issuers);
			removeLoader();
		}).catch(err => {
			removeLoader();
		});

		return () => {
			window.removeEventListener('resize', handleResize);
		};
	}, [protocols]);


	useEffect(() => {
		const fetchIssuers = async () => {
			try {
				const response = await api.getExternalEntity('/legal_person/issuers/all');
				const fetchedIssuers = response.data;
				setIssuers(fetchedIssuers);
				setFilteredIssuers(fetchedIssuers);
			} catch (error) {
				console.error('Error fetching issuers:', error);
			}
		};

		fetchIssuers();
	}, [api]);

	const handleSearch = (event) => {
		const query = event.target.value;
		setSearchQuery(query);
	};

	useEffect(() => {
		const filtered = issuers.filter((issuer) => {
			const friendlyName = issuer.selectedDisplay.name.toLowerCase();
			const query = searchQuery.toLowerCase();
			return friendlyName.includes(query);
		});

		setFilteredIssuers(filtered);
	}, [searchQuery, issuers]);

	const handleIssuerClick = async (credentialIssuerIdentifier) => {
		const clickedIssuer = credentialIssuers.find((issuer) => issuer.credentialIssuerIdentifier === credentialIssuerIdentifier);
		if (clickedIssuer) {
			const cl = protocols.openID4VCIClients[credentialIssuerIdentifier];
			if (!cl) {
				return;
			}
			const confs = await cl.getAvailableCredentialConfigurations();
			setAvailableCredentialConfigurations(confs);
			setSelectedIssuer(clickedIssuer);
			setShowRedirectPopup(true);
		}
	};

	const handleCancel = () => {
		setShowRedirectPopup(false);
		setSelectedIssuer(null);
	};

	const handleContinue = (selectedConfiguration) => {
		setLoading(true);

		console.log("Seelected issuer = ", selectedIssuer)
		if (selectedIssuer && selectedIssuer.credentialIssuerIdentifier) {
			const cl = protocols.openID4VCIClients[selectedIssuer.credentialIssuerIdentifier];
			console.log("Selected configuration = ", selectedConfiguration)
			const userHandleB64u = keystore.getUserHandleB64u();
			if (userHandleB64u == null) {
				console.error("Could not generate authorization request because user handle is null");
				return;
			}
			cl.generateAuthorizationRequest(selectedConfiguration, userHandleB64u).then(({ url, client_id, request_uri }) => {
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
			}).catch((err) => {
				console.error(err)
				console.error("Couldn't generate authz req")
			});
		}

		setLoading(false);
		setShowRedirectPopup(false);
	};

	// QR Code part
	const [isQRScannerOpen, setQRScannerOpen] = useState(false);

	const openQRScanner = () => {
		setQRScannerOpen(true);
	};

	const closeQRScanner = () => {
		setQRScannerOpen(false);
	};

	return (
		<>
			<div className="sm:px-6 w-full">
				<H1 heading={t('common.navItemAddCredentials')}>
					<QRButton openQRScanner={openQRScanner} isSmallScreen={isSmallScreen} />
				</H1>
				<p className="italic text-gray-700 dark:text-gray-300">{t('pageAddCredentials.description')}</p>

				<div className="my-4">
					<input
						type="text"
						placeholder={t('pageAddCredentials.searchPlaceholder')}
						className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 dark:bg-gray-800 dark:text-white rounded-lg focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:inputDarkModeOverride"
						value={searchQuery}
						onChange={handleSearch}
					/>
				</div>
				{credentialIssuers.length === 0 ? (
					<p className="text-gray-700 dark:text-gray-300 mt-4">{t('pageAddCredentials.noFound')}</p>
				) : (
					<div
						className="max-h-screen-80 overflow-y-auto space-y-2"
						style={{ maxHeight: '80vh' }}
					>
						{credentialIssuers.map((issuer) => (
							<button
								key={issuer.credentialIssuerIdentifier}
								className="bg-white px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md cursor-pointer hover:bg-gray-100 dark:bg-gray-800 dark:hover:bg-gray-700 dark:text-white break-words w-full text-left"
								style={{ wordBreak: 'break-all' }}
								onClick={() => handleIssuerClick(issuer.credentialIssuerIdentifier)}
								disabled={!isOnline}
								title={!isOnline ? t('common.offlineTitle') : ''}
							>
								<div dangerouslySetInnerHTML={{ __html: highlightBestSequence(issuer.selectedDisplay.name, searchQuery) }} />
							</button>
						))}
					</div>
				)}
			</div>

			{showRedirectPopup && (
				<RedirectPopup
					loading={loading}
					handleClose={handleCancel}
					handleContinue={handleContinue}
					availableCredentialConfigurations={availableCredentialConfigurations}
					popupTitle={`${t('pageAddCredentials.popup.title')} ${selectedIssuer?.selectedDisplay.name}`}
					popupMessage={t('pageAddCredentials.popup.message')}
				/>
			)}

			{/* QR Code Scanner Modal */}
			{isQRScannerOpen && (
				<QRCodeScanner
					onClose={closeQRScanner}
				/>
			)}

		</>
	);
};

export default Issuers;
