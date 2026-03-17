import { defineConfig } from "tsup";

export default defineConfig({
	entry: ["src/main.ts"],
	format: ["esm"],
	dts: true,
	bundle: true,
	splitting: false,
	platform: "node",
	target: "node20",
	noExternal: [/^@arikernel\//],
	external: ["better-sqlite3", "ulid", "yaml", "zod"],
	banner: {
		js: "#!/usr/bin/env node",
	},
});
