/**
 * SHA-256 hash chain for tamper-evident audit logging.
 *
 * Provides local tamper evidence: any modification, deletion, or insertion
 * of events breaks the chain. When an HMAC key is provided, each hash is
 * an HMAC-SHA256 keyed digest — an attacker with filesystem access cannot
 * recompute valid hashes without the key.
 *
 * For production deployments, forward events to an external append-only
 * store (SIEM, CloudTrail, immutable log) for defense-in-depth.
 */
import { createHash, createHmac } from "node:crypto";

const GENESIS_HASH = "0".repeat(64);

/**
 * Compute a chain hash over (previousHash || data).
 * If an HMAC key is provided, uses HMAC-SHA256 so an attacker cannot
 * forge hashes without the key — even with full SQLite access.
 */
export function computeHash(data: string, previousHash: string, hmacKey?: Buffer): string {
	if (hmacKey) {
		return createHmac("sha256", hmacKey).update(previousHash).update(data).digest("hex");
	}
	return createHash("sha256").update(previousHash).update(data).digest("hex");
}

export function genesisHash(): string {
	return GENESIS_HASH;
}

export function verifyChain(
	events: Array<{ hash: string; previousHash: string; data: string }>,
	hmacKey?: Buffer,
): {
	valid: boolean;
	brokenAt?: number;
} {
	for (let i = 0; i < events.length; i++) {
		const event = events[i];
		const expected = computeHash(event.data, event.previousHash, hmacKey);
		if (expected !== event.hash) {
			return { valid: false, brokenAt: i };
		}
		if (i > 0 && event.previousHash !== events[i - 1].hash) {
			return { valid: false, brokenAt: i };
		}
	}
	return { valid: true };
}
