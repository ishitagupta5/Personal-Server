import { requireAuthentication } from '$lib/auth.js';

/** @type {import('./$types').PageLoad} */
export async function load(loadArgs) {
	const { fetch } = loadArgs;
	const user = await requireAuthentication(loadArgs);
	const res = await fetch('/api/video');
	const videos = res.json();
	return { videos, user };
}

export const ssr = false;
export const prerender = false;
