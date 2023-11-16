import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig, splitVendorChunkPlugin } from 'vite';

// for development, proxy /api and *.mp4 to the pserv backend
const backend = 'http://localhost:10001';

export default defineConfig({
	plugins: [sveltekit(), splitVendorChunkPlugin()],
    // as per https://rollupjs.org/configuration-options/#output-manualchunks
    // and https://vitejs.dev/guide/build.html#chunking-strategy
    build: {
      rollupOptions: {
        output: {
          manualChunks: () => 'bundle',
        },
      },
    },
	ssr: {
		noExternal: ['@popperjs/core']
	},
	server: {
		proxy: {
			'/api': {
				target: backend,
				changeOrigin: true
			},
			'^/.*.mp4$': {
				target: backend,
				changeOrigin: true
			}
		}
	}
});
