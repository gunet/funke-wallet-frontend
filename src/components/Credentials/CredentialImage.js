import { useState, useEffect } from "react";
import { parseCredential } from "../../functions/parseCredential";
import StatusRibbon from '../../components/Credentials/StatusRibbon';
import ausweis_card from '../../assets/images/ausweis_card.png';


export const CredentialImage = ({ credential, className, onClick, showRibbon = true }) => {
	const [parsedCredential, setParsedCredential] = useState(null);

	useEffect(() => {
		if (credential) {
			parseCredential(credential).then((c) => {
				setParsedCredential(c);
			});
		}
	}, [credential]);

	return (
		<>
			{parsedCredential && (
				<>
					<img src={parsedCredential?.credentialBranding?.image?.url ?? ausweis_card} alt={"Credential"} className={className} onClick={onClick} />
					{showRibbon &&
						<StatusRibbon credential={credential} />
					}
				</>
			)}
			{!parsedCredential && <div className={className}>Credential is deleted</div>}
		</>
	);
};
