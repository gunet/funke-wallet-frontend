import axios from 'axios';
import { IHttpClient } from '../interfaces/IHttpClient';

// @ts-ignore
const walletBackendServerUrl = process.env.REACT_APP_WALLET_BACKEND_URL;

export class HttpClient implements IHttpClient {
	async get(url: string, headers: any): Promise<any> {
		const response = await axios.post(`${walletBackendServerUrl}/proxy`, {
			headers: headers,
			url: url,
			method: 'get',
		}, {
			headers: {
				Authorization: 'Bearer ' + JSON.parse(sessionStorage.getItem('appToken'))
			}
		})
		return response.data;
	}

	async post(url: string, body: any, headers: any): Promise<any> {
		const response = await axios.post(`${walletBackendServerUrl}/proxy`, {
			headers: headers,
			url: url,
			method: 'post',
			data: body,
		}, {
			headers: {
				Authorization: 'Bearer ' + JSON.parse(sessionStorage.getItem('appToken'))
			}
		});
		return response.data;
	}
}