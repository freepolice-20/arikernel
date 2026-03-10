import { describe, expect, it } from "vitest";
import { TokenStore } from "../src/token-store.js";
import type { CapabilityGrant } from "@arikernel/core";

function makeGrant(id: string, nonce?: string): CapabilityGrant {
	const now = new Date();
	return {
		id,
		requestId: `req-${id}`,
		principalId: "agent-001",
		capabilityClass: "file.read",
		constraints: { allowedPaths: ["./workspace/**"] },
		lease: {
			issuedAt: now.toISOString(),
			expiresAt: new Date(now.getTime() + 5 * 60 * 1000).toISOString(),
			maxCalls: 10,
			callsUsed: 0,
		},
		taintContext: [],
		revoked: false,
		nonce,
	};
}

describe("TokenStore nonce tracking", () => {
	it("accepts a fresh nonce", () => {
		const store = new TokenStore();
		const reused = store.checkAndRecordNonce("nonce-001");
		expect(reused).toBe(false);
	});

	it("detects nonce reuse", () => {
		const store = new TokenStore();
		store.checkAndRecordNonce("nonce-001");
		const reused = store.checkAndRecordNonce("nonce-001");
		expect(reused).toBe(true);
	});

	it("allows different nonces", () => {
		const store = new TokenStore();
		expect(store.checkAndRecordNonce("nonce-001")).toBe(false);
		expect(store.checkAndRecordNonce("nonce-002")).toBe(false);
		expect(store.checkAndRecordNonce("nonce-001")).toBe(true);
	});

	it("stores grants with nonces", () => {
		const store = new TokenStore();
		const grant = makeGrant("g1", "my-nonce");
		store.store(grant);
		const retrieved = store.get("g1");
		expect(retrieved?.nonce).toBe("my-nonce");
	});
});
