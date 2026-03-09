/**
 * SHA-256 hash chain for tamper-evident audit logging.
 *
 * Provides local tamper evidence: any modification, deletion, or insertion
 * of events breaks the chain. Does NOT provide completeness guarantees
 * against full database replacement or host-level compromise.
 *
 * For production deployments, forward events to an external append-only
 * store (SIEM, CloudTrail, immutable log) for defense-in-depth.
 */
import { createHash } from 'node:crypto';

const GENESIS_HASH = '0'.repeat(64);

export function computeHash(data: string, previousHash: string): string {
	return createHash('sha256')
		.update(previousHash)
		.update(data)
		.digest('hex');
}

export function genesisHash(): string {
	return GENESIS_HASH;
}

export function verifyChain(
	events: Array<{ hash: string; previousHash: string; data: string }>,
): { valid: boolean; brokenAt?: number } {
	for (let i = 0; i < events.length; i++) {
		const event = events[i];
		const expected = computeHash(event.data, event.previousHash);
		if (expected !== event.hash) {
			return { valid: false, brokenAt: i };
		}
		if (i > 0 && event.previousHash !== events[i - 1].hash) {
			return { valid: false, brokenAt: i };
		}
	}
	return { valid: true };
}
