import { writable, get } from 'svelte/store';
import { getUser } from '$lib/auth';

// Create a custom store with a method to set the `fetch` function
export const fetchStore = writable(undefined);

function createUser() {
	const { subscribe, set } = writable(undefined, function start(set) {
		const fetch = get(fetchStore);
		getUser(fetch).then((user) => set(user));
		return () => {};
	});

	return {
		subscribe,
		logout: () => set(null),
		login: (user) => {
			set(user);
		}
	};
}

export const user = createUser();
