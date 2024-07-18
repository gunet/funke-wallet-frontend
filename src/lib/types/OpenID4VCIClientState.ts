/**
 * serializable
 */
export class OpenID4VCIClientState {
	
	constructor() { }

	public serialize(): string {
		throw new Error("Not impl")
	}

	public static deserialize(storedValue: string): OpenID4VCIClientState {
		throw new Error("Not impl")
	}
}