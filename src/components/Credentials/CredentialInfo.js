import React, { useEffect, useState } from 'react';
import { BiSolidCategoryAlt, BiSolidUserCircle } from 'react-icons/bi';
import { AiFillCalendar } from 'react-icons/ai';
import { RiPassExpiredFill, RiPassValidFill } from 'react-icons/ri';
import { MdTitle, MdGrade, MdOutlineNumbers, MdFlag, MdLocalPolice, MdHome } from 'react-icons/md';
import { TbRating12Plus, TbRating14Plus, TbRating16Plus, TbRating18Plus, TbRating21Plus, TbCirclePlus } from "react-icons/tb";
import { GiLevelEndFlag } from 'react-icons/gi';
import { formatDate } from '../../functions/DateFormat';
import { parseCredential } from '../../functions/parseCredential';

const getFieldIcon = (fieldName) => {
	switch (fieldName) {
		case 'type':
			return <BiSolidCategoryAlt size={25} className="inline mr-1" />;
		case 'expdate':
			return <RiPassExpiredFill size={25} className="inline mr-1" />;
		case 'issuanceDate':
			return <RiPassValidFill size={25} className="inline mr-1" />;
		case 'dateOfBirth':
			return <AiFillCalendar size={25} className="inline mr-1" />;
		case 'over12':
			return <TbRating12Plus size={25} className="inline mr-1" />;
		case 'over14':
			return <TbRating14Plus size={25} className="inline mr-1" />;
		case 'over16':
			return <TbRating16Plus size={25} className="inline mr-1" />;
		case 'over18':
			return <TbRating18Plus size={25} className="inline mr-1" />;
		case 'over21':
			return <TbRating21Plus size={25} className="inline mr-1" />;
		case 'over':
			return <TbCirclePlus size={25} className="inline mr-1" />;
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
		case 'address':
			return <MdHome size={25} className="inline mr-1" />;
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

const CredentialInfo = ({ credential, mainClassName = "text-xs sm:text-sm md:text-base pt-5 pr-2 w-full", displayAgeFields = 'false', displayExtraFields = 'false'}) => {

	const [parsedCredential, setParsedCredential] = useState(null);


	useEffect(() => {
		if (credential) {
			parseCredential(credential, true).then((c) => {
				setParsedCredential(c);
			});
		}
	}, [credential]);

	return (
		<div className={mainClassName}>
			<table className="lg:w-4/5">
				<tbody className="divide-y-4 divide-transparent">
					{parsedCredential && (
						<>
							{parsedCredential?.issuance_date && renderRow('issuanceDate', 'Issuance', formatDate(parsedCredential?.issuance_date))}
							{parsedCredential?.iat && renderRow('issuanceDate', 'Issuance', formatDate(new Date(parsedCredential?.iat * 1000)))}
							{parsedCredential?.exp && renderRow('expdate', 'Expiration', formatDate(new Date(parsedCredential?.exp * 1000)))}
							{parsedCredential?.expiry_date && renderRow('expdate', 'Expiration', formatDate(parsedCredential?.expiry_date))}
							{renderRow('familyName', 'Family Name', parsedCredential?.familyName)}
							{renderRow('familyName', 'Family Name', parsedCredential?.family_name)}
							{renderRow('familyName', 'Given Name', parsedCredential?.given_name)}
							{renderRow('familyName', 'Birth Family Name', parsedCredential?.birth_family_name)}
							{renderRow('placeOfBirth', 'Place of Birth', parsedCredential?.place_of_birth?.locality)}
							{renderRow('placeOfBirth', 'Place of Birth', parsedCredential?.birth_place)}
							{renderRow('issuingCountry', 'Issuing Country', parsedCredential?.issuing_country)}
							{renderRow('issuingCountry', 'Issuing Authority', parsedCredential?.issuing_authority)}
							{renderRow('issuingCountry', 'Issuing Company', parsedCredential?.issuing_company)}
							{renderRow('firstName', 'First Name', parsedCredential?.firstName)}
							{renderRow('id', 'Personal ID', parsedCredential?.personalIdentifier)}
							{renderRow('dateOfBirth', 'Birthday', parsedCredential?.dateOfBirth)}
							{renderRow('dateOfBirth', 'Birthday', parsedCredential?.birthdate)}
							{renderRow('dateOfBirth', 'Birthday', parsedCredential?.birth_date)}
							{displayAgeFields === 'true' && (
								<>
									{renderRow('over12', 'Age Over 12', parsedCredential?.age_equal_or_over ? parsedCredential?.age_equal_or_over['12'] : null)}
									{renderRow('over14', 'Age Over 14', parsedCredential?.age_equal_or_over ? parsedCredential?.age_equal_or_over['14'] : null)}
									{renderRow('over16', 'Age Over 16', parsedCredential?.age_equal_or_over ? parsedCredential?.age_equal_or_over['16'] : null)}
									{renderRow('over18', 'Age Over 18', parsedCredential?.age_equal_or_over ? parsedCredential?.age_equal_or_over['18'] : null)}
									{renderRow('over21', 'Age Over 21', parsedCredential?.age_equal_or_over ? parsedCredential?.age_equal_or_over['21'] : null)}

									{renderRow('over12', 'Age Over 12', parsedCredential?.age_over_12)}
									{renderRow('over14', 'Age Over 14', parsedCredential?.age_over_14)}
									{renderRow('over16', 'Age Over 16', parsedCredential?.age_over_16)}
									{renderRow('over18', 'Age Over 18', parsedCredential?.age_over_18)}
									{renderRow('over21', 'Age Over 21', parsedCredential?.age_over_21)}
									{renderRow('over', 'Age Over 65', parsedCredential?.age_over_65)}

								</>
							)}
							{displayExtraFields === 'true' && (
								<>
									{renderRow('address', 'Address (City)', parsedCredential?.address?.locality)}
									{renderRow('address', 'Address (Postal Code)', parsedCredential?.address?.postal_code)}
									{renderRow('address', 'Address (Street)', parsedCredential?.address?.street_address)}
									{renderRow('dateOfBirth', 'Birthday (Year)', parsedCredential?.age_birth_year)}
									{renderRow('dateOfBirth', 'Age in years', parsedCredential?.age_in_years)}
								</>
							)}
						</>
					)}
				</tbody>
			</table>
		</div>
	);
};

export default CredentialInfo;
