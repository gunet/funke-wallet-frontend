import React, { createContext, useState, useCallback, useContext } from 'react';
import { useApi } from '../api';
import { extractCredentialFriendlyName } from '../functions/extractCredentialFriendlyName';
import OnlineStatusContext from '../context/OnlineStatusContext';
import { useCommunicationProtocols } from '../components/useCommunicationProtocols';

const CredentialsContext = createContext();

export const CredentialsProvider = ({ children }) => {
	const { isOnline } = useContext(OnlineStatusContext);
	const api = useApi(isOnline);
	const [vcEntityList, setVcEntityList] = useState([]);
	const [latestCredentials, setLatestCredentials] = useState(new Set());

	const protocols = useCommunicationProtocols();
	const getData = useCallback(async () => {
		try {
			const response = await api.get('/storage/vc');
			const fetchedVcList = response.data.vc_list;
			const vcEntityList = await Promise.all(fetchedVcList.map(async vcEntity => {
				const name = await extractCredentialFriendlyName(vcEntity);
				return { ...vcEntity, friendlyName: name };
			}));
			vcEntityList.sort((vcA, vcB) => new Date(vcB.issuanceDate) - new Date(vcA.issuanceDate));

			const latestIssuanceDate = vcEntityList[0]?.issuanceDate;
			const latestCreds = new Set(vcEntityList.filter(vc => vc.issuanceDate === latestIssuanceDate).map(vc => vc.id));

			if (window.location.pathname.includes('/cb')) {
				setLatestCredentials(latestCreds);
				setTimeout(() => {
					setLatestCredentials(new Set());
				}, 2000);
			} else {
				setLatestCredentials(new Set());
			}

			setVcEntityList(vcEntityList);
		} catch (error) {
			console.error('Failed to fetch data', error);
		}
	}, [api, protocols]);

	return (
		<CredentialsContext.Provider value={{ vcEntityList, latestCredentials, getData }}>
			{children}
		</CredentialsContext.Provider>
	);
};

export default CredentialsContext;
