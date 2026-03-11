import {
	createPrivateKey,
	createPublicKey,
	generateKeyPairSync,
	randomBytes,
	sign,
	verify,
} from "node:crypto";
import type { DecisionVerdict, PolicyRule, TaintLabel } from "@arikernel/core";
import type { DecisionResponse } from "./types.js";

/**
 * DER prefix for Ed25519 PKCS#8 private key wrapping a 32-byte seed.
 * RFC 8410 §7 — the full DER is this prefix + 32-byte raw seed.
 */
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/**
 * Signs enforcement decisions with Ed25519.
 *
 * The canonical payload is a deterministic JSON string of the decision fields
 * (excluding the signature itself). The nonce provides replay protection —
 * each decision gets a unique 16-byte random value.
 */
export class DecisionSigner {
	private readonly privateKey: ReturnType<typeof createPrivateKey>;
	private readonly publicKey: ReturnType<typeof createPublicKey>;

	/**
	 * Create a signer from a hex-encoded 32-byte Ed25519 seed.
	 * The public key is derived automatically.
	 */
	constructor(hexSeed: string) {
		const seed = Buffer.from(hexSeed, "hex");
		if (seed.length !== 32) {
			throw new Error("Ed25519 signing key must be exactly 32 bytes (64 hex characters)");
		}

		const pkcs8Der = Buffer.concat([ED25519_PKCS8_PREFIX, seed]);
		this.privateKey = createPrivateKey({ key: pkcs8Der, format: "der", type: "pkcs8" });
		this.publicKey = createPublicKey(this.privateKey);
	}

	/**
	 * Build and sign a decision response.
	 */
	sign(params: {
		decision: DecisionVerdict;
		reason: string;
		policyVersion: string;
		policyHash: string;
		kernelBuild: string;
		timestamp: string;
		matchedRule?: PolicyRule;
		taintLabels: TaintLabel[];
	}): DecisionResponse {
		const nonce = randomBytes(16).toString("hex");
		const decisionId = `dec-${Date.now()}-${randomBytes(4).toString("hex")}`;

		const canonical = this.canonicalize({
			decision: params.decision,
			decisionId,
			kernelBuild: params.kernelBuild,
			nonce,
			policyHash: params.policyHash,
			policyVersion: params.policyVersion,
			reason: params.reason,
			timestamp: params.timestamp,
		});

		const sig = sign(null, Buffer.from(canonical, "utf-8"), this.privateKey);

		return {
			decision: params.decision,
			decisionId,
			reason: params.reason,
			policyVersion: params.policyVersion,
			policyHash: params.policyHash,
			kernelBuild: params.kernelBuild,
			timestamp: params.timestamp,
			nonce,
			signature: sig.toString("hex"),
			matchedRule: params.matchedRule ?? undefined,
			taintLabels: params.taintLabels,
		};
	}

	/**
	 * Verify a signed decision response.
	 * Returns true if the signature is valid and the nonce has not been seen.
	 */
	verify(response: DecisionResponse, nonceStore?: NonceStore): boolean {
		if (nonceStore && !nonceStore.claim(response.nonce)) {
			return false;
		}

		const canonical = this.canonicalize({
			decision: response.decision,
			decisionId: response.decisionId,
			kernelBuild: response.kernelBuild,
			nonce: response.nonce,
			policyHash: response.policyHash,
			policyVersion: response.policyVersion,
			reason: response.reason,
			timestamp: response.timestamp,
		});

		try {
			const sig = Buffer.from(response.signature, "hex");
			return verify(null, Buffer.from(canonical, "utf-8"), this.publicKey, sig);
		} catch {
			return false;
		}
	}

	/**
	 * Export the public key as hex-encoded raw bytes (32 bytes → 64 hex chars).
	 * Clients use this to verify signatures without possessing the private seed.
	 */
	get publicKeyHex(): string {
		const spki = this.publicKey.export({ format: "der", type: "spki" });
		// SPKI DER for Ed25519 is 44 bytes: 12-byte header + 32-byte raw key
		return (spki as Buffer).subarray(12).toString("hex");
	}

	/**
	 * Deterministic JSON serialization of the signed fields.
	 * Keys are sorted alphabetically to ensure canonical form.
	 */
	private canonicalize(fields: Record<string, string>): string {
		return JSON.stringify(fields, Object.keys(fields).sort());
	}
}

/**
 * Verify-only counterpart of DecisionSigner.
 * Accepts a hex-encoded 32-byte Ed25519 public key (no private key needed).
 */
export class DecisionVerifier {
	private readonly publicKey: ReturnType<typeof createPublicKey>;

	constructor(hexPublicKey: string) {
		const raw = Buffer.from(hexPublicKey, "hex");
		if (raw.length !== 32) {
			throw new Error("Ed25519 public key must be exactly 32 bytes (64 hex characters)");
		}
		// Wrap raw 32-byte key in SPKI DER envelope
		const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
		const spkiDer = Buffer.concat([spkiPrefix, raw]);
		this.publicKey = createPublicKey({ key: spkiDer, format: "der", type: "spki" });
	}

	verify(response: DecisionResponse, nonceStore?: NonceStore): boolean {
		if (nonceStore && !nonceStore.claim(response.nonce)) {
			return false;
		}

		const fields = {
			decision: response.decision,
			decisionId: response.decisionId,
			kernelBuild: response.kernelBuild,
			nonce: response.nonce,
			policyHash: response.policyHash,
			policyVersion: response.policyVersion,
			reason: response.reason,
			timestamp: response.timestamp,
		};
		const canonical = JSON.stringify(
			fields,
			Object.keys(fields).sort(),
		);

		try {
			const sig = Buffer.from(response.signature, "hex");
			return verify(null, Buffer.from(canonical, "utf-8"), this.publicKey, sig);
		} catch {
			return false;
		}
	}
}

/**
 * Time-windowed nonce store for replay protection.
 * Nonces expire after `windowMs` to bound memory usage.
 */
export class NonceStore {
	private readonly seen = new Map<string, number>();
	private readonly windowMs: number;

	constructor(windowMs = 300_000) {
		this.windowMs = windowMs;
	}

	/**
	 * Attempt to claim a nonce. Returns true if the nonce is fresh,
	 * false if it was already seen (replay attempt).
	 */
	claim(nonce: string): boolean {
		this.evict();
		if (this.seen.has(nonce)) {
			return false;
		}
		this.seen.set(nonce, Date.now());
		return true;
	}

	private evict(): void {
		const cutoff = Date.now() - this.windowMs;
		for (const [nonce, ts] of this.seen) {
			if (ts < cutoff) {
				this.seen.delete(nonce);
			}
		}
	}

	get size(): number {
		return this.seen.size;
	}
}

/**
 * Generate a fresh Ed25519 keypair. Returns the 32-byte seed as hex.
 * Useful for tests and initial setup.
 */
export function generateSigningKey(): string {
	const { privateKey } = generateKeyPairSync("ed25519");
	const pkcs8 = privateKey.export({ format: "der", type: "pkcs8" });
	// PKCS#8 DER for Ed25519 is 48 bytes: 16-byte header + 32-byte seed
	return (pkcs8 as Buffer).subarray(16).toString("hex");
}
