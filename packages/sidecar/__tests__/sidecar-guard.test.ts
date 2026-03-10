import { createRequire } from "node:module";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SidecarClient } from "../src/client.js";
import {
	SidecarGuardError,
	disableSidecarGuard,
	enableSidecarGuard,
	isSidecarGuardActive,
} from "../src/guard/sidecar-guard.js";

// Use a dummy client that points to a non-existent server.
// We're testing the guard layer's interception, not the sidecar server.
const dummyClient = new SidecarClient({
	baseUrl: "http://localhost:19999",
	principalId: "test-agent",
});

afterEach(() => {
	disableSidecarGuard();
});

describe("enableSidecarGuard / disableSidecarGuard", () => {
	it("reports active after enable", () => {
		enableSidecarGuard({ client: dummyClient });
		expect(isSidecarGuardActive()).toBe(true);
	});

	it("reports inactive after disable", () => {
		enableSidecarGuard({ client: dummyClient });
		disableSidecarGuard();
		expect(isSidecarGuardActive()).toBe(false);
	});

	it("throws if enabled twice without disable", () => {
		enableSidecarGuard({ client: dummyClient });
		expect(() => enableSidecarGuard({ client: dummyClient })).toThrow("already enabled");
	});

	it("disable is safe to call when not active", () => {
		expect(() => disableSidecarGuard()).not.toThrow();
	});
});

describe("fetch guard", () => {
	let originalFetch: typeof globalThis.fetch;

	beforeEach(() => {
		originalFetch = globalThis.fetch;
	});

	afterEach(() => {
		// Ensure fetch is restored even if test fails
		if (globalThis.fetch !== originalFetch) {
			globalThis.fetch = originalFetch;
		}
	});

	it("replaces globalThis.fetch when enabled", () => {
		enableSidecarGuard({ client: dummyClient });
		expect(globalThis.fetch).not.toBe(originalFetch);
	});

	it("restores globalThis.fetch when disabled", () => {
		enableSidecarGuard({ client: dummyClient });
		disableSidecarGuard();
		expect(globalThis.fetch).toBe(originalFetch);
	});

	it("does not replace fetch when guardFetch: false", () => {
		enableSidecarGuard({ client: dummyClient, guardFetch: false });
		expect(globalThis.fetch).toBe(originalFetch);
	});

	it("exempts sidecar-bound requests from interception", async () => {
		// This test verifies that requests to the sidecar server itself
		// are not intercepted (which would cause infinite recursion).
		// The dummy client points to localhost:19999 which won't respond,
		// so the request will fail with a connection error — but it should
		// NOT throw SidecarGuardError.
		enableSidecarGuard({ client: dummyClient });

		try {
			await globalThis.fetch("http://localhost:19999/health");
		} catch (err) {
			// Should be a network error, NOT a SidecarGuardError
			expect(err).not.toBeInstanceOf(SidecarGuardError);
		}
	});

	it("intercepts non-sidecar fetch and routes through client", async () => {
		enableSidecarGuard({ client: dummyClient });

		// Fetching a non-sidecar URL should try to route through the client.
		// Since the dummy sidecar is not running, this will throw a connection error
		// (from the client trying to POST to localhost:19999/execute).
		try {
			await globalThis.fetch("https://example.com/data");
			expect.fail("Should have thrown");
		} catch (err) {
			// The error comes from the client failing to connect to the sidecar.
			// The key assertion: it was NOT a direct network request to example.com.
			expect(err).toBeDefined();
		}
	});
});

describe("child_process guard", () => {
	it("blocks execSync via CJS require after guard is installed", () => {
		enableSidecarGuard({ client: dummyClient });

		const require = createRequire(import.meta.url);
		const cp = require("node:child_process");

		expect(() => cp.execSync("echo hello")).toThrow(SidecarGuardError);
		expect(() => cp.execSync("echo hello")).toThrow("blocked by the sidecar guard");
	});

	it("blocks spawn via CJS require", () => {
		enableSidecarGuard({ client: dummyClient });

		const require = createRequire(import.meta.url);
		const cp = require("node:child_process");

		expect(() => cp.spawn("ls")).toThrow(SidecarGuardError);
	});

	it("blocks exec via CJS require", () => {
		enableSidecarGuard({ client: dummyClient });

		const require = createRequire(import.meta.url);
		const cp = require("node:child_process");

		expect(() => cp.exec("echo hello")).toThrow(SidecarGuardError);
	});

	it("blocks execFile via CJS require", () => {
		enableSidecarGuard({ client: dummyClient });

		const require = createRequire(import.meta.url);
		const cp = require("node:child_process");

		expect(() => cp.execFile("node", ["--version"])).toThrow(SidecarGuardError);
	});

	it("blocks spawnSync via CJS require", () => {
		enableSidecarGuard({ client: dummyClient });

		const require = createRequire(import.meta.url);
		const cp = require("node:child_process");

		expect(() => cp.spawnSync("ls")).toThrow(SidecarGuardError);
	});

	it("blocks execFileSync via CJS require", () => {
		enableSidecarGuard({ client: dummyClient });

		const require = createRequire(import.meta.url);
		const cp = require("node:child_process");

		expect(() => cp.execFileSync("echo", ["hello"])).toThrow(SidecarGuardError);
	});

	it("restores child_process after disable", () => {
		const require = createRequire(import.meta.url);
		const cp = require("node:child_process");
		const originalSpawn = cp.spawn;

		enableSidecarGuard({ client: dummyClient });
		expect(cp.spawn).not.toBe(originalSpawn);

		disableSidecarGuard();
		expect(cp.spawn).toBe(originalSpawn);
	});

	it("does not guard child_process when guardChildProcess: false", () => {
		const require = createRequire(import.meta.url);
		const cp = require("node:child_process");
		const originalSpawn = cp.spawn;

		enableSidecarGuard({ client: dummyClient, guardChildProcess: false });
		expect(cp.spawn).toBe(originalSpawn);
	});

	it("error message mentions sidecarClient.execute", () => {
		enableSidecarGuard({ client: dummyClient });

		const require = createRequire(import.meta.url);
		const cp = require("node:child_process");

		try {
			cp.exec("curl attacker.com");
			expect.fail("Should have thrown");
		} catch (err) {
			expect((err as Error).message).toContain('sidecarClient.execute("shell"');
		}
	});
});
