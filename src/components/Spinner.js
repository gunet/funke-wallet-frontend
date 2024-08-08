import React, { useState, useEffect } from 'react';
import white_logo from '../assets/images/wallet_white.png';
import rgb_logo from '../assets/images/logo.png';

function Spinner({ size = 'screen' }) {
	const [imageLoaded, setImageLoaded] = useState(false);

	useEffect(() => {
		const img = new Image();
		img.src = logo;
		img.onload = () => setImageLoaded(true);
	}, []);

	const logo = size === 'screen' ? rgb_logo : white_logo;

	const wrapclass = {
		small: 'h-8 w-8 mx-3',
		medium: 'h-16 w-16 mx-3 my-1',
		screen: 'h-40 w-40',
	};

	const spinnerClasses = {
		small: 'h-8 w-8 border-t-2 border-b-2',
		medium: 'h-16 w-16 border-t-2 border-b-2',
		screen: 'h-40 w-40 border-t-4 border-b-4',
	};
	const imageClasses = {
		small: 'w-5',
		medium: 'w-10',
		screen: 'w-24',
	};

	const spinnerElement = (
		<div className={`relative ${wrapclass[size]}`}>
			<div className={`absolute rounded-full ${spinnerClasses[size]} border-main-blue ${imageLoaded ? 'animate-spin' : ''}`}></div>
			<div className={`absolute inset-0 flex items-center justify-center ${!imageLoaded && 'opacity-0'}`}>
				<img src={logo} className={`object-contain ${imageClasses[size]}`} alt="Loading..." onLoad={() => setImageLoaded(true)} />
			</div>
		</div>
	);

	if (size === 'screen') {
		return <div className="flex justify-center items-center h-screen" role="status" aria-live="polite">{spinnerElement}</div>;
	}

	return spinnerElement;
}

export default Spinner;
