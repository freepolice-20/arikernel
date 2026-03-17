import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		// Benchmark scenarios make real HTTP calls via tool executors.
		// CI network latency can exceed the default 5s timeout.
		testTimeout: 30_000,
	},
});
