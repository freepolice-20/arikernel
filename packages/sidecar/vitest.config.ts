import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		// Run test files sequentially to avoid TCP port conflicts in CI
		fileParallelism: false,
	},
});
