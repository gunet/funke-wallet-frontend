import React, { createContext, useState, useCallback, useContext, useEffect } from 'react';
import { useCommunicationProtocols } from '../components/useCommunicationProtocols';


const CommunicationProtocolsContext = createContext(null);

export const CommunicationProtocolsProvider = ({ children }) => {

	const { protocols } = useCommunicationProtocols();

	return (
		<CommunicationProtocolsContext.Provider value={{ protocols }}>
			{children}
		</CommunicationProtocolsContext.Provider>
	);
}

export default CommunicationProtocolsContext;
