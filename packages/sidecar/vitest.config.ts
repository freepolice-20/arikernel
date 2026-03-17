import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		// Run test files sequentially to avoid TCP port conflicts in CI
		fileParallelism: false,
		// Integration tests make real HTTP calls that can exceed 5s in CI
		testTimeout: 30_000,
	},
});
