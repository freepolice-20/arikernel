import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	createCapabilityToken,
	deserializeCapabilityToken,
	generateNonce,
	serializeCapabilityToken,
	verifyCapabilityToken,
} from "../src/capability-token.js";
import type { HmacSigningKey } from "../src/capability-token.js";
import type { CapabilityGrant } from "../src/types/capability.js";

function makeHmacKey(): HmacSigningKey {
	return { algorithm: "hmac-sha256", secret: randomBytes(32) };
}

function makeGrant(overrides?: Partial<CapabilityGrant>): CapabilityGrant {
	const now = new Date();
	return {
		id: "grant-001",
		requestId: "req-001",
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
		...overrides,
	};
}

describe("Nonce generation", () => {
	it("generates unique 64-char hex nonces", () => {
		const n1 = generateNonce();
		const n2 = generateNonce();
		expect(n1).toHaveLength(64);
		expect(n2).toHaveLength(64);
		expect(n1).not.toBe(n2);
		expect(/^[0-9a-f]{64}$/.test(n1)).toBe(true);
	});
});

describe("Nonce in signed tokens", () => {
	const key = makeHmacKey();

	it("nonce is included in the canonical payload and affects signature", () => {
		const grant1 = makeGrant({ nonce: "nonce-aaa" });
		const grant2 = makeGrant({ nonce: "nonce-bbb" });

		const token1 = createCapabilityToken(grant1, key);
		const token2 = createCapabilityToken(grant2, key);

		// Different nonces produce different signatures
		expect(token1.signature).not.toBe(token2.signature);
	});

	it("token with nonce verifies correctly", () => {
		const grant = makeGrant({ nonce: generateNonce() });
		const token = createCapabilityToken(grant, key);
		const result = verifyCapabilityToken(token, key);
		expect(result.valid).toBe(true);
	});

	it("mutating nonce invalidates signature", () => {
		const grant = makeGrant({ nonce: "original-nonce" });
		const token = createCapabilityToken(grant, key);

		const mutated = {
			...token,
			grant: { ...token.grant, nonce: "tampered-nonce" },
		};
		const result = verifyCapabilityToken(mutated, key);
		expect(result.valid).toBe(false);
		expect(result.reason).toContain("Invalid signature");
	});

	it("round-trips nonce through serialization", () => {
		const nonce = generateNonce();
		const grant = makeGrant({ nonce });
		const token = createCapabilityToken(grant, key);

		const serialized = serializeCapabilityToken(token);
		const deserialized = deserializeCapabilityToken(serialized);

		expect(deserialized.grant.nonce).toBe(nonce);
		const result = verifyCapabilityToken(deserialized, key);
		expect(result.valid).toBe(true);
	});

	it("token without nonce still verifies (backward compat)", () => {
		const grant = makeGrant(); // no nonce
		const token = createCapabilityToken(grant, key);
		const result = verifyCapabilityToken(token, key);
		expect(result.valid).toBe(true);
	});
});
