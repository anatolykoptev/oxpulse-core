import { defineConfig } from 'vitest/config';

export default defineConfig({
	test: {
		environment: 'node',
		include: ['src/**/*.test.ts', 'src/**/__tests__/**/*.test.ts'],
		// Skipped pending @oxpulse/wire-codec@0.3.1 — current 0.3.0 npm dist
		// emits `import './dicts'` without `.js` extension, which breaks Node
		// ESM resolver (works under vite/bundler resolver in oxpulse-chat
		// workspace). Tests pass green in oxpulse-chat workspace.
		exclude: [
			'**/node_modules/**',
			'src/wrap.test.ts',
			'src/__tests__/bundle-composer.test.ts',
			// Same wire-codec import-extension issue transitively:
			'src/__tests__/transport-crypto.test.ts',
		],
	},
});
