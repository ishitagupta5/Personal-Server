import { fetchStore } from '$lib/userstore.js';

/** @type {import('./$types').PageLoad} */
export async function load(loadArgs) {
	const { fetch } = loadArgs;
	fetchStore.set(fetch);
	return {};
}

export const prerender = true;
export const ssr = true;
