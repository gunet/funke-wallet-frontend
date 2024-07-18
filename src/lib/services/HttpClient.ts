import { IHttpClient } from '../interfaces/IHttpClient';

export class HttpClient implements IHttpClient {
	async get(url: string, headers: any): Promise<Response> {
		const response = await fetch(url, {
			method: 'GET',
			headers: headers,
		});
		return response;
	}
	async post(url: string, body: any, headers: any): Promise<Response> {
		const response = await fetch(url, {
			method: 'POST',
			headers: headers,
			body: JSON.stringify(body),
		});
		
		return response;
	}
}