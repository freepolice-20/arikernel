import { generateKeyPairSync, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	createCapabilityToken,
	deserializeCapabilityToken,
	serializeCapabilityToken,
	verifyCapabilityToken,
} from "../src/capability-token.js";
import type { Ed25519SigningKey, HmacSigningKey } from "../src/capability-token.js";
import type { CapabilityGrant } from "../src/types/capability.js";

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

function makeHmacKey(): HmacSigningKey {
	return { algorithm: "hmac-sha256", secret: randomBytes(32) };
}

function makeEd25519Key(): Ed25519SigningKey {
	const { publicKey, privateKey } = generateKeyPairSync("ed25519");
	return {
		algorithm: "ed25519",
		privateKey: Buffer.from(privateKey.export({ type: "pkcs8", format: "pem" }) as string),
		publicKey: Buffer.from(publicKey.export({ type: "spki", format: "pem" }) as string),
	};
}

describe("Signed Capability Tokens — HMAC-SHA256", () => {
	const key = makeHmacKey();

	it("creates and verifies a valid token", () => {
		const grant = makeGrant();
		const token = createCapabilityToken(grant, key);

		expect(token.signature).toBeTruthy();
		expect(token.algorithm).toBe("hmac-sha256");

		const result = verifyCapabilityToken(token, key);
		expect(result.valid).toBe(true);
	});

	it("rejects a forged token (wrong signature)", () => {
		const grant = makeGrant();
		const token = createCapabilityToken(grant, key);

		// Tamper with the signature
		const forged = { ...token, signature: `AAAA${token.signature.slice(4)}` };
		const result = verifyCapabilityToken(forged, key);
		expect(result.valid).toBe(false);
		expect(result.reason).toContain("Invalid signature");
	});

	it("rejects a token with modified constraints", () => {
		const grant = makeGrant();
		const token = createCapabilityToken(grant, key);

		// Mutate the constraints after signing
		const mutated = {
			...token,
			grant: {
				...token.grant,
				constraints: { allowedPaths: ["/**"] },
			},
		};
		const result = verifyCapabilityToken(mutated, key);
		expect(result.valid).toBe(false);
		expect(result.reason).toContain("Invalid signature");
	});

	it("rejects a token with modified capabilityClass", () => {
		const grant = makeGrant();
		const token = createCapabilityToken(grant, key);

		const mutated = {
			...token,
			grant: {
				...token.grant,
				capabilityClass: "shell.exec" as unknown as typeof token.grant.capabilityClass,
			},
		};
		const result = verifyCapabilityToken(mutated, key);
		expect(result.valid).toBe(false);
		expect(result.reason).toContain("Invalid signature");
	});

	it("rejects an expired token", () => {
		const past = new Date(Date.now() - 10_000);
		const grant = makeGrant({
			lease: {
				issuedAt: new Date(past.getTime() - 60_000).toISOString(),
				expiresAt: past.toISOString(),
				maxCalls: 10,
				callsUsed: 0,
			},
		});
		const token = createCapabilityToken(grant, key);
		const result = verifyCapabilityToken(token, key);
		expect(result.valid).toBe(false);
		expect(result.reason).toContain("expired");
	});

	it("rejects a token that has exhausted its usage limit", () => {
		const grant = makeGrant({
			lease: {
				issuedAt: new Date().toISOString(),
				expiresAt: new Date(Date.now() + 300_000).toISOString(),
				maxCalls: 1,
				callsUsed: 1,
			},
		});
		const token = createCapabilityToken(grant, key);
		const result = verifyCapabilityToken(token, key);
		expect(result.valid).toBe(false);
		expect(result.reason).toContain("exhausted");
	});

	it("rejects a token signed with a different key", () => {
		const grant = makeGrant();
		const token = createCapabilityToken(grant, key);

		const otherKey = makeHmacKey();
		const result = verifyCapabilityToken(token, otherKey);
		expect(result.valid).toBe(false);
		expect(result.reason).toContain("Invalid signature");
	});

	it("rejects algorithm mismatch", () => {
		const grant = makeGrant();
		const token = createCapabilityToken(grant, key);

		const ed25519Key = makeEd25519Key();
		const result = verifyCapabilityToken(token, ed25519Key);
		expect(result.valid).toBe(false);
		expect(result.reason).toContain("Algorithm mismatch");
	});
});

describe("Signed Capability Tokens — Ed25519", () => {
	const key = makeEd25519Key();

	it("creates and verifies a valid token", () => {
		const grant = makeGrant();
		const token = createCapabilityToken(grant, key);

		expect(token.signature).toBeTruthy();
		expect(token.algorithm).toBe("ed25519");

		const result = verifyCapabilityToken(token, key);
		expect(result.valid).toBe(true);
	});

	it("rejects a forged token", () => {
		const grant = makeGrant();
		const token = createCapabilityToken(grant, key);

		const forged = { ...token, signature: `AAAA${token.signature.slice(4)}` };
		const result = verifyCapabilityToken(forged, key);
		expect(result.valid).toBe(false);
		expect(result.reason).toContain("Invalid signature");
	});

	it("rejects modified constraints", () => {
		const grant = makeGrant();
		const token = createCapabilityToken(grant, key);

		const mutated = {
			...token,
			grant: {
				...token.grant,
				constraints: { allowedPaths: ["/etc/**"] },
			},
		};
		const result = verifyCapabilityToken(mutated, key);
		expect(result.valid).toBe(false);
		expect(result.reason).toContain("Invalid signature");
	});

	it("rejects a token signed with a different Ed25519 key", () => {
		const grant = makeGrant();
		const token = createCapabilityToken(grant, key);

		const otherKey = makeEd25519Key();
		const result = verifyCapabilityToken(token, otherKey);
		expect(result.valid).toBe(false);
		expect(result.reason).toContain("Invalid signature");
	});
});

describe("Token serialization", () => {
	const key = makeHmacKey();

	it("round-trips through serialize/deserialize", () => {
		const grant = makeGrant();
		const token = createCapabilityToken(grant, key);

		const serialized = serializeCapabilityToken(token);
		expect(typeof serialized).toBe("string");

		const deserialized = deserializeCapabilityToken(serialized);
		expect(deserialized.grant.id).toBe(token.grant.id);
		expect(deserialized.signature).toBe(token.signature);
		expect(deserialized.algorithm).toBe(token.algorithm);

		// Deserialized token should still verify
		const result = verifyCapabilityToken(deserialized, key);
		expect(result.valid).toBe(true);
	});

	it("detects tampering in serialized form", () => {
		const grant = makeGrant();
		const token = createCapabilityToken(grant, key);
		const serialized = serializeCapabilityToken(token);

		// Decode, tamper, re-encode
		const json = JSON.parse(Buffer.from(serialized, "base64").toString("utf8"));
		json.grant.constraints.allowedPaths = ["/**"];
		const tampered = Buffer.from(JSON.stringify(json), "utf8").toString("base64");

		const deserialized = deserializeCapabilityToken(tampered);
		const result = verifyCapabilityToken(deserialized, key);
		expect(result.valid).toBe(false);
		expect(result.reason).toContain("Invalid signature");
	});
});

describe("Mutable fields do not affect signature", () => {
	const key = makeHmacKey();

	it("callsUsed changes do not invalidate the signature", () => {
		const grant = makeGrant();
		const token = createCapabilityToken(grant, key);

		// Simulate usage increment (as TokenStore.consume does)
		token.grant.lease.callsUsed = 5;

		const result = verifyCapabilityToken(token, key);
		expect(result.valid).toBe(true);
	});

	it("revoked flag does not invalidate the signature", () => {
		const grant = makeGrant();
		const token = createCapabilityToken(grant, key);

		token.grant.revoked = true;

		// Signature is still valid — revocation is checked separately by TokenStore
		const result = verifyCapabilityToken(token, key);
		expect(result.valid).toBe(true);
	});
});
