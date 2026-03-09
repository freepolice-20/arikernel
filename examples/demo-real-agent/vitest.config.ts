import { defineConfig } from 'vitest/config';

export default defineConfig({
	test: {
		root: './examples/demo-real-agent',
		include: ['*.test.ts'],
		testTimeout: 120_000,
	},
});
