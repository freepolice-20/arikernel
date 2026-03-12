import { randomBytes } from "node:crypto";
import type { HmacSigningKey } from "@arikernel/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Firewall } from "../src/index.js";

function makeHmacKey(): HmacSigningKey {
	return { algorithm: "hmac-sha256", secret: randomBytes(32) };
}

const ALLOW_ALL_POLICY = {
	id: "allow-all",
	name: "Allow all",
	priority: 100,
	match: {} as const,
	decision: "allow" as const,
};

describe("Secure mode capability token enforcement", () => {
	let firewall: Firewall;
	const signingKey = makeHmacKey();

	beforeEach(() => {
		firewall = new Firewall({
			principal: {
				name: "test-agent",
				capabilities: [
					{ toolClass: "file", actions: ["read", "write"] },
					{ toolClass: "http", actions: ["get", "post"] },
				],
			},
			policies: [ALLOW_ALL_POLICY],
			auditLog: ":memory:",
			signingKey,
			securityMode: "secure",
		});

		firewall.registerExecutor({
			toolClass: "file",
			execute: async (tc) => ({
				callId: tc.id,
				success: true,
				data: "file contents",
				taintLabels: [],
			}),
		});
	});

	afterEach(() => {
		try {
			firewall.close();
		} catch {}
	});

	it("denies execution without a capability token in secure mode", async () => {
		await expect(
			firewall.execute({
				toolClass: "file",
				action: "read",
				parameters: { path: "./test.txt" },
			}),
		).rejects.toThrow(/Capability token required/);
	});

	it("allows execution with a valid capability grant", async () => {
		const decision = firewall.requestCapability("file.read");
		expect(decision.granted).toBe(true);
		expect(decision.grant?.nonce).toBeTruthy();

		const result = await firewall.execute({
			toolClass: "file",
			action: "read",
			parameters: { path: "./test.txt" },
			grantId: decision.grant?.id,
		});

		expect(result.success).toBe(true);
	});

	it("grants contain unique nonces", () => {
		const d1 = firewall.requestCapability("file.read");
		const d2 = firewall.requestCapability("file.read");

		expect(d1.grant?.nonce).toBeTruthy();
		expect(d2.grant?.nonce).toBeTruthy();
		expect(d1.grant?.nonce).not.toBe(d2.grant?.nonce);
	});

	it("nonce is 64 hex characters", () => {
		const decision = firewall.requestCapability("file.read");
		expect(decision.grant?.nonce).toMatch(/^[0-9a-f]{64}$/);
	});
});

describe("Dev mode backward compatibility", () => {
	let firewall: Firewall;

	beforeEach(() => {
		firewall = new Firewall({
			principal: {
				name: "dev-agent",
				capabilities: [{ toolClass: "file", actions: ["read"] }],
			},
			policies: [ALLOW_ALL_POLICY],
			auditLog: ":memory:",
			securityMode: "dev",
		});

		firewall.registerExecutor({
			toolClass: "file",
			execute: async (tc) => ({
				callId: tc.id,
				success: true,
				data: "ok",
				taintLabels: [],
			}),
		});
	});

	afterEach(() => {
		try {
			firewall.close();
		} catch {}
	});

	it("allows execution with a grant in dev mode", async () => {
		const decision = firewall.requestCapability("file.read");
		expect(decision.granted).toBe(true);

		const result = await firewall.execute({
			toolClass: "file",
			action: "read",
			parameters: { path: "./test.txt" },
			grantId: decision.grant?.id,
		});

		expect(result.success).toBe(true);
	});

	it("grants still have nonces in dev mode", () => {
		const decision = firewall.requestCapability("file.read");
		expect(decision.grant?.nonce).toBeTruthy();
	});
});

describe("Security mode defaults", () => {
	it("defaults to secure when signingKey is provided", async () => {
		const fw = new Firewall({
			principal: { name: "a", capabilities: [{ toolClass: "file" }] },
			policies: [ALLOW_ALL_POLICY],
			auditLog: ":memory:",
			signingKey: makeHmacKey(),
		});

		fw.registerExecutor({
			toolClass: "file",
			execute: async (tc) => ({ callId: tc.id, success: true, data: "", taintLabels: [] }),
		});

		await expect(fw.execute({ toolClass: "file", action: "read", parameters: {} })).rejects.toThrow(
			/Capability token required/,
		);

		try {
			fw.close();
		} catch {}
	});

	it("defaults to dev when no signingKey", async () => {
		const fw = new Firewall({
			principal: { name: "a", capabilities: [{ toolClass: "file" }] },
			policies: [ALLOW_ALL_POLICY],
			auditLog: ":memory:",
		});

		fw.registerExecutor({
			toolClass: "file",
			execute: async (tc) => ({ callId: tc.id, success: true, data: "", taintLabels: [] }),
		});

		// In dev mode with tokenStore present, tokens are still enforced by default.
		// But without a grant, it requires a token. The key difference is
		// dev mode doesn't require cryptographic signing.
		const decision = fw.requestCapability("file.read");
		expect(decision.granted).toBe(true);

		const result = await fw.execute({
			toolClass: "file",
			action: "read",
			parameters: {},
			grantId: decision.grant?.id,
		});
		expect(result.success).toBe(true);

		try {
			fw.close();
		} catch {}
	});
});
