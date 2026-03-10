/**
 * Signed Capability Tokens
 *
 * Provides cryptographic signing and verification for capability grants,
 * preventing token forgery, constraint mutation, and unauthorized reuse.
 *
 * Supports two signing modes:
 * - HMAC-SHA256: simple shared-secret deployments
 * - Ed25519: multi-process / sidecar deployments with asymmetric keys
 */
import {
	createHmac,
	createPrivateKey,
	createPublicKey,
	randomBytes,
	sign,
	timingSafeEqual,
	verify,
} from "node:crypto";
import type { CapabilityGrant } from "./types/capability.js";

export type SigningAlgorithm = "hmac-sha256" | "ed25519";

export interface HmacSigningKey {
	algorithm: "hmac-sha256";
	/** Shared secret — minimum 32 bytes recommended. */
	secret: Buffer;
}

export interface Ed25519SigningKey {
	algorithm: "ed25519";
	/** PKCS8 or raw 32-byte private key. */
	privateKey: Buffer;
	/** SPKI or raw 32-byte public key. */
	publicKey: Buffer;
}

export type SigningKey = HmacSigningKey | Ed25519SigningKey;

export interface SignedCapabilityToken {
	/** The grant this token represents. */
	grant: CapabilityGrant;
	/** Base64-encoded cryptographic signature over the canonical payload. */
	signature: string;
	/** Algorithm used to produce the signature. */
	algorithm: SigningAlgorithm;
}

export interface TokenVerificationResult {
	valid: boolean;
	reason?: string;
}

/**
 * Canonical payload for signing — deterministic JSON of the immutable
 * grant fields. Mutable fields (callsUsed, revoked) are excluded so
 * the signature remains valid across usage increments.
 */
function canonicalPayload(grant: CapabilityGrant): string {
	return JSON.stringify({
		id: grant.id,
		requestId: grant.requestId,
		principalId: grant.principalId,
		capabilityClass: grant.capabilityClass,
		constraints: grant.constraints,
		lease: {
			issuedAt: grant.lease.issuedAt,
			expiresAt: grant.lease.expiresAt,
			maxCalls: grant.lease.maxCalls,
		},
		taintContext: grant.taintContext,
		nonce: grant.nonce,
	});
}

/**
 * Generate a cryptographically random nonce for replay protection.
 * Returns a 32-byte hex string (256 bits of entropy).
 */
export function generateNonce(): string {
	return randomBytes(32).toString("hex");
}

function signHmac(payload: string, secret: Buffer): string {
	return createHmac("sha256", secret).update(payload, "utf8").digest("base64");
}

function makeEd25519PrivateKey(buf: Buffer) {
	if (buf.length === 32) {
		return createPrivateKey({
			key: { kty: "OKP", crv: "Ed25519", d: buf.toString("base64url") },
			format: "jwk",
		});
	}
	return createPrivateKey({ key: buf, format: "pem" });
}

function makeEd25519PublicKey(buf: Buffer) {
	if (buf.length === 32) {
		return createPublicKey({
			key: { kty: "OKP", crv: "Ed25519", x: buf.toString("base64url") },
			format: "jwk",
		});
	}
	return createPublicKey({ key: buf, format: "pem" });
}

function signEd25519(payload: string, privateKeyBuf: Buffer): string {
	const privateKey = makeEd25519PrivateKey(privateKeyBuf);
	return sign(null, Buffer.from(payload, "utf8"), privateKey).toString("base64");
}

function verifyEd25519(payload: string, signature: Buffer, publicKeyBuf: Buffer): boolean {
	const publicKey = makeEd25519PublicKey(publicKeyBuf);
	return verify(null, Buffer.from(payload, "utf8"), publicKey, signature);
}

/**
 * Create a signed capability token from a grant.
 */
export function createCapabilityToken(
	grant: CapabilityGrant,
	signingKey: SigningKey,
): SignedCapabilityToken {
	const payload = canonicalPayload(grant);

	let signature: string;
	if (signingKey.algorithm === "hmac-sha256") {
		signature = signHmac(payload, signingKey.secret);
	} else {
		signature = signEd25519(payload, signingKey.privateKey);
	}

	return {
		grant,
		signature,
		algorithm: signingKey.algorithm,
	};
}

/**
 * Verify a signed capability token's cryptographic integrity.
 *
 * Checks:
 * 1. Signature matches the canonical payload (forgery / mutation detection)
 * 2. Expiry has not passed
 * 3. Usage limit has not been exceeded
 */
export function verifyCapabilityToken(
	token: SignedCapabilityToken,
	signingKey: SigningKey,
): TokenVerificationResult {
	const payload = canonicalPayload(token.grant);

	// Step 1: Verify algorithm match
	if (token.algorithm !== signingKey.algorithm) {
		return {
			valid: false,
			reason: `Algorithm mismatch: token uses '${token.algorithm}', key uses '${signingKey.algorithm}'`,
		};
	}

	// Step 2: Verify cryptographic signature
	let signatureValid: boolean;
	if (signingKey.algorithm === "hmac-sha256") {
		const expected = signHmac(payload, signingKey.secret);
		const a = Buffer.from(token.signature, "base64");
		const b = Buffer.from(expected, "base64");
		signatureValid = a.length === b.length && timingSafeEqual(a, b);
	} else {
		const sig = Buffer.from(token.signature, "base64");
		signatureValid = verifyEd25519(payload, sig, signingKey.publicKey);
	}

	if (!signatureValid) {
		return { valid: false, reason: "Invalid signature: token may have been forged or modified" };
	}

	// Step 3: Verify expiry
	const expiresAt = new Date(token.grant.lease.expiresAt).getTime();
	if (Date.now() > expiresAt) {
		return { valid: false, reason: `Token expired at ${token.grant.lease.expiresAt}` };
	}

	// Step 4: Verify usage limit
	if (token.grant.lease.callsUsed >= token.grant.lease.maxCalls) {
		return {
			valid: false,
			reason: `Token exhausted: ${token.grant.lease.callsUsed}/${token.grant.lease.maxCalls} calls used`,
		};
	}

	return { valid: true };
}

/**
 * Serialize a signed token to a portable string (base64-encoded JSON).
 */
export function serializeCapabilityToken(token: SignedCapabilityToken): string {
	return Buffer.from(JSON.stringify(token), "utf8").toString("base64");
}

/**
 * Deserialize a token from a portable string.
 */
export function deserializeCapabilityToken(serialized: string): SignedCapabilityToken {
	const json = Buffer.from(serialized, "base64").toString("utf8");
	return JSON.parse(json) as SignedCapabilityToken;
}
