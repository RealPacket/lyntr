import { json } from '@sveltejs/kit';
import type { RequestHandler } from '@sveltejs/kit';
import { verifyAuthJWT } from '@/server/jwt';
import { minioClient } from '@/server/minio';
import { v4 as uuidv4 } from 'uuid';
import { config } from 'dotenv';
import { uploadAvatar } from '../util';
import { isImageNsfw, NSFW_ERROR } from '@/moderation';

config();

const ratelimits = new Map();

export const POST: RequestHandler = async ({ request, cookies }) => {
	const authCookie = cookies.get('_TOKEN__DO_NOT_SHARE');

	if (!authCookie) {
		return json({ error: 'Missing authentication' }, { status: 401 });
	}

	try {
		const jwtPayload = await verifyAuthJWT(authCookie);

		if (!jwtPayload.userId) {
			throw new Error('Invalid JWT token');
		}
		const { userId } = jwtPayload;
		const ratelimit = ratelimits.get(userId);

		if (!ratelimit) {
			ratelimits.set(userId, Date.now());
		} else if (Math.round((Date.now() - ratelimit) / 1000) < 5) {
			return json({ error: 'You are ratelimited.' }, { status: 429 });
		} else {
			ratelimits.delete(userId);
		}

		const formData = await request.formData();

		const file = formData.get('file') as File;

		if (!file) {
			return json({ error: 'No file uploaded' }, { status: 400 });
		}

		const fileName = jwtPayload.userId;

		const arrayBuffer = await file.arrayBuffer();
		const inputBuffer = Buffer.from(arrayBuffer);

		if(await isImageNsfw(inputBuffer)) {
			return NSFW_ERROR
		}

		// compression
		uploadAvatar(inputBuffer, fileName, minioClient);

		return json(
			{
				message: 'File uploaded successfully'
			},
			{ status: 200 }
		);
	} catch (error) {
		console.error('File upload error:', error);
		return json({ error: 'File upload failed' }, { status: 500 });
	}
};
