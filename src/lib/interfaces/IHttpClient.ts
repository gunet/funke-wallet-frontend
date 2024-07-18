export interface IHttpClient {
	get(url: string, headers: any): Promise<Response>;
	post(url: string, body: any, headers: any): Promise<Response>;
}