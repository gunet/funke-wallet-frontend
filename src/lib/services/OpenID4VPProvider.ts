import { IHttpClient } from "../interfaces/IHttpClient";
import { IOpenID4VPProvider } from "../interfaces/IOpenID4VPProvider";


export class OpenID4VPProvider implements IOpenID4VPProvider {
  private httpClient: IHttpClient;

  constructor(httpClient: IHttpClient) {
    this.httpClient = httpClient;
  }



} 