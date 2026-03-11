import { describe, expect, it } from "vitest";
import { DecisionSigner, DecisionVerifier, NonceStore, generateSigningKey } from "../src/signer.js";

const TEST_KEY = generateSigningKey();

const SIGN_PARAMS = {
	decision: "allow" as const,
	reason: "test",
	policyVersion: "1.0.0",
	policyHash: "abcdef0123456789",
	kernelBuild: "test-build",
	timestamp: "2026-01-01T00:00:00.000Z",
	taintLabels: [],
};

describe("DecisionSigner", () => {
	it("rejects keys that are not exactly 32 bytes", () => {
		expect(() => new DecisionSigner("abcd")).toThrow("exactly 32 bytes");
		expect(() => new DecisionSigner("a".repeat(66))).toThrow("exactly 32 bytes");
	});

	it("signs a decision and produces a hex Ed25519 signature", () => {
		const signer = new DecisionSigner(TEST_KEY);
		const response = signer.sign(SIGN_PARAMS);

		// Ed25519 signatures are 64 bytes = 128 hex chars
		expect(response.signature).toMatch(/^[0-9a-f]{128}$/);
		expect(response.nonce).toMatch(/^[0-9a-f]{32}$/);
		expect(response.decision).toBe("allow");
		expect(response.decisionId).toMatch(/^dec-\d+-[0-9a-f]{8}$/);
		expect(response.policyHash).toBe("abcdef0123456789");
	});

	it("verifies a valid signature", () => {
		const signer = new DecisionSigner(TEST_KEY);
		const response = signer.sign({
			...SIGN_PARAMS,
			decision: "deny",
			reason: "blocked",
			policyVersion: "2.0.0",
			timestamp: new Date().toISOString(),
		});

		expect(signer.verify(response)).toBe(true);
	});

	it("rejects a tampered signature", () => {
		const signer = new DecisionSigner(TEST_KEY);
		const response = signer.sign(SIGN_PARAMS);

		response.decision = "deny"; // tamper
		expect(signer.verify(response)).toBe(false);
	});

	it("rejects a tampered policyHash", () => {
		const signer = new DecisionSigner(TEST_KEY);
		const response = signer.sign(SIGN_PARAMS);

		response.policyHash = "tampered1234567"; // tamper
		expect(signer.verify(response)).toBe(false);
	});

	it("rejects a tampered decisionId", () => {
		const signer = new DecisionSigner(TEST_KEY);
		const response = signer.sign(SIGN_PARAMS);

		response.decisionId = "dec-000-tampered"; // tamper
		expect(signer.verify(response)).toBe(false);
	});

	it("rejects signature from a different key", () => {
		const signer1 = new DecisionSigner(TEST_KEY);
		const signer2 = new DecisionSigner(generateSigningKey());

		const response = signer1.sign(SIGN_PARAMS);
		expect(signer2.verify(response)).toBe(false);
	});

	it("each signature has a unique nonce and decisionId", () => {
		const signer = new DecisionSigner(TEST_KEY);

		const r1 = signer.sign(SIGN_PARAMS);
		const r2 = signer.sign(SIGN_PARAMS);
		expect(r1.nonce).not.toBe(r2.nonce);
		expect(r1.decisionId).not.toBe(r2.decisionId);
		expect(r1.signature).not.toBe(r2.signature);
	});

	it("exports public key as 32-byte hex", () => {
		const signer = new DecisionSigner(TEST_KEY);
		expect(signer.publicKeyHex).toMatch(/^[0-9a-f]{64}$/);
	});
});

describe("DecisionVerifier", () => {
	it("verifies signatures using only the public key", () => {
		const signer = new DecisionSigner(TEST_KEY);
		const verifier = new DecisionVerifier(signer.publicKeyHex);

		const response = signer.sign(SIGN_PARAMS);
		expect(verifier.verify(response)).toBe(true);
	});

	it("rejects tampered responses", () => {
		const signer = new DecisionSigner(TEST_KEY);
		const verifier = new DecisionVerifier(signer.publicKeyHex);

		const response = signer.sign(SIGN_PARAMS);
		response.reason = "tampered";
		expect(verifier.verify(response)).toBe(false);
	});

	it("rejects wrong public key", () => {
		const signer = new DecisionSigner(TEST_KEY);
		const otherSigner = new DecisionSigner(generateSigningKey());
		const wrongVerifier = new DecisionVerifier(otherSigner.publicKeyHex);

		const response = signer.sign(SIGN_PARAMS);
		expect(wrongVerifier.verify(response)).toBe(false);
	});
});

describe("NonceStore", () => {
	it("claims a fresh nonce", () => {
		const store = new NonceStore();
		expect(store.claim("abc123")).toBe(true);
	});

	it("rejects a replayed nonce", () => {
		const store = new NonceStore();
		store.claim("abc123");
		expect(store.claim("abc123")).toBe(false);
	});

	it("rejects replay when used with signer.verify", () => {
		const signer = new DecisionSigner(TEST_KEY);
		const store = new NonceStore();

		const response = signer.sign(SIGN_PARAMS);

		expect(signer.verify(response, store)).toBe(true);
		// Replaying the same response should fail
		expect(signer.verify(response, store)).toBe(false);
	});

	it("evicts expired nonces", () => {
		const store = new NonceStore(1); // 1ms window
		store.claim("old-nonce");

		// Wait for eviction
		const start = Date.now();
		while (Date.now() - start < 5) {
			/* spin */
		}

		// After eviction, same nonce can be claimed again
		expect(store.claim("old-nonce")).toBe(true);
	});
});

describe("generateSigningKey", () => {
	it("produces a valid 32-byte hex seed", () => {
		const key = generateSigningKey();
		expect(key).toMatch(/^[0-9a-f]{64}$/);
		// Should be usable as a signing key
		const signer = new DecisionSigner(key);
		const response = signer.sign(SIGN_PARAMS);
		expect(signer.verify(response)).toBe(true);
	});
});
