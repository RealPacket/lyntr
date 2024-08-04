/**
 * We'll use the key pair generated in the last step
 * to derive the symmetric cryptographic key that encrypts
 * and decrypts data and is unique for any two communicating users.
 * For example,
 * User A derives the key using their private key with User B's public key,
 * and User B derives the same key using their private key and User A's public key.
 * No one can generate the derived key without access to at least one of the users' private keys,
 * so it's essential to keep them safe.
 */

import { verifyAuthJWT } from "@/server/jwt";
import { json } from "@sveltejs/kit";
import { db } from '@/server/db';
import { users, messages, followers, lynts, likes } from '@/server/schema';
import { eq } from "drizzle-orm";

interface KeyExchangeRequest {
    publicKeyJwk: string; // example: thisisbase64encoded==
    recipientId: string; //  example: 123456 (user ID, @exampleuser)
}

/*
the sender will POST their public key to the server and the server will relay that to the recipient,
the recipient will GET the sender's public key from the server,
then the recipient will POST their public key to the server and the server will relay that to the sender,
and then the sender will GET the recipient's public key from the server.
while the key hasn't been sent to the server yet, the request will yield.
*/

const pendingPublicKeys: Map</*sender: */string, /*data: */KeyExchangeRequest> = new Map();
const ratelimits = new Map();

export async function POST({ request }) {
    // The JSON contains 2 things: the public key, and the recipient of that public key.
    const data = await request.json();

    const { publicKeyJwk, recipientId } = data as KeyExchangeRequest;
    pendingPublicKeys.set(recipientId, { publicKeyJwk, recipientId });
    return json({}, { status: 200 });
}

export async function GET({ request: _, cookies, url }) {
    const senderId = url.searchParams.get('sender');
    const authCookie = cookies.get('_TOKEN__DO_NOT_SHARE');
    if (!authCookie) {
        return json({error: "Missing authentication"}, { status: 401 });
    }
    
	try {
		const jwtPayload = await verifyAuthJWT(authCookie);

		if (!jwtPayload.userId) {
			throw new Error('Invalid JWT token');
		}

		const user = await db
			.select({
				id: users.id,
				username: users.username,
				handle: users.handle,
				created_at: users.created_at,
				iq: users.iq
			})
			.from(users)
			.where(eq(users.id, jwtPayload.userId))
			.limit(1);

		if (user.length === 0) {
			return json({ error: 'User not found' }, { status: 403 });
		}

		const user_id = user[0].id;

		const ratelimit = ratelimits.get(user_id);
		if (!ratelimit) {
			ratelimits.set(user_id, Date.now());
		} else if (Math.round((Date.now() - ratelimit) / 1000) < 5) {
			return json({ error: 'You are ratelimited.' }, { status: 429 });
		} else {
			ratelimits.delete(user_id);
		}
    } catch {}
    if (!senderId) {
        return json({error: "Missing sender"}, { status: 400 });
    }
    if (pendingPublicKeys.has(senderId)) {
        const { publicKeyJwk } = pendingPublicKeys.get(senderId) as KeyExchangeRequest;
        pendingPublicKeys.delete(senderId);
        return json({ publicKeyJwk }, { status: 200 });
    }
    return json({ error: 'Pending public key not found' }, { status: 404 });
}