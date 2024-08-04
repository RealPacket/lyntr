// I need to export it in a different file so others can access it.
export interface KeyExchangeRequest {
    publicKeyJwk: JsonWebKey; // example: thisisbase64encoded==
    recipientId: string; //  example: 123456 (user ID, @exampleuser)
}

export const pendingPublicKeys: Map</*sender: */string, /*data: */KeyExchangeRequest> = new Map();

export default pendingPublicKeys;
