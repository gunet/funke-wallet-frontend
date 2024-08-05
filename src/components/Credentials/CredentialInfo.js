import React, { useEffect, useState } from 'react';
import { BiSolidCategoryAlt, BiSolidUserCircle } from 'react-icons/bi';
import { AiFillCalendar } from 'react-icons/ai';
import { RiPassExpiredFill } from 'react-icons/ri';
import { MdTitle, MdGrade, MdOutlineNumbers, MdFlag, MdLocalPolice } from 'react-icons/md';
import { TbRating18Plus } from "react-icons/tb";
import { GiLevelEndFlag } from 'react-icons/gi';
import { formatDate } from '../../functions/DateFormat';
import { parseCredential } from '../../functions/parseCredential';
import { useCommunicationProtocols } from '../useCommunicationProtocols';

const getFieldIcon = (fieldName) => {
	switch (fieldName) {
		case 'type':
			return <BiSolidCategoryAlt size={25} className="inline mr-1" />;
		case 'expdate':
			return <RiPassExpiredFill size={25} className="inline mr-1" />;
		case 'dateOfBirth':
			return <AiFillCalendar size={25} className="inline mr-1" />;
		case 'over18':
			return <TbRating18Plus size={25} className="inline mr-1" />;
		case 'id':
			return <MdOutlineNumbers size={25} className="inline mr-1" />;
		case 'familyName':
		case 'firstName':
			return <BiSolidUserCircle size={25} className="inline mr-1" />;
		case 'diplomaTitle':
			return <MdTitle size={25} className="inline mr-1" />;
		case 'eqfLevel':
			return <GiLevelEndFlag size={25} className="inline mr-1" />;
		case 'grade':
			return <MdGrade size={25} className="inline mr-1" />;
		case 'placeOfBirth':
			return <MdFlag size={25} className="inline mr-1" />;
		case 'issuingCountry':
			return <MdLocalPolice size={25} className="inline mr-1" />;
		default:
			return null;
	}
};

const renderRow = (fieldName, label, fieldValue) => {
	if (fieldValue) {
		const isBoolean = typeof fieldValue === 'boolean';
		return (
			<tr className="text-left">
				<td className="font-bold text-primary dark:text-primary-light py-2 px-2 rounded-l-xl">
					<div className="flex md:flex-row flex-col items-left">
						{getFieldIcon(fieldName)}
						<span className="md:ml-1 flex items-center">{label}:</span>
					</div>
				</td>
				<td className="text-gray-700 dark:text-white py-2 px-2 rounded-r-xl">
					{isBoolean ? (fieldValue ? 'Yes' : 'No') : fieldValue}
				</td>
			</tr>
		);
	} else {
		return null;
	}
};

const CredentialInfo = ({ credential, mainClassName = "text-xs sm:text-sm md:text-base pt-5 pr-2 w-full" }) => {

	const [parsedCredential, setParsedCredential] = useState(null);

	useEffect(() => {
		parseCredential(credential).then((c) => {
			setParsedCredential(c);
		});
	}, [credential]);

	useEffect(() => {
		parseCredential(credential).then((c) => {
			setParsedCredential(c);
		});
	}, [credential]);

	return (
		<div className={mainClassName}>
			<table className="lg:w-4/5">
				<tbody className="divide-y-4 divide-transparent">
					{parsedCredential && (
						<>
							{renderRow('expdate', 'Expiration', formatDate(parsedCredential?.exp))}
							{renderRow('familyName', 'Family Name', parsedCredential?.familyName)}
							{renderRow('familyName', 'Family Name', parsedCredential?.family_name)}
							{renderRow('familyName', 'Given Name', parsedCredential?.given_name)}
							{renderRow('placeOfBirth', 'Place of Birth', parsedCredential?.place_of_birth?.locality)}
							{renderRow('issuingCountry', 'Issuing Country', parsedCredential?.issuing_country)}
							{renderRow('firstName', 'First Name', parsedCredential?.firstName)}
							{renderRow('id', 'Personal ID', parsedCredential?.personalIdentifier)}
							{renderRow('dateOfBirth', 'Birthday', parsedCredential?.dateOfBirth)}
							{renderRow('dateOfBirth', 'Birthday', parsedCredential?.birthdate)}
							{renderRow('over18', 'Age Over 18', parsedCredential?.age_equal_or_over ? parsedCredential?.age_equal_or_over['18'] : null)}
							{renderRow('over18', 'Age Over 18', parsedCredential?.age_over_18)}
						</>
					)}
				</tbody>
			</table>
		</div>
	);
};

export default CredentialInfo;
