import type { CapabilityGrant, SigningAlgorithm } from "@arikernel/core";

export interface TokenValidation {
	valid: boolean;
	reason?: string;
}

export interface StoredToken {
	grant: CapabilityGrant;
	/** Base64-encoded signature, present when signing is enabled. */
	signature?: string;
	/** Signing algorithm used, present when signing is enabled. */
	algorithm?: SigningAlgorithm;
}

export class TokenStore {
	private grants = new Map<string, StoredToken>();
	private usedNonces = new Set<string>();

	store(grant: CapabilityGrant, signature?: string, algorithm?: SigningAlgorithm): void {
		this.grants.set(grant.id, { grant, signature, algorithm });
	}

	/**
	 * Check whether a nonce has already been used (replay detection).
	 * Records the nonce atomically — returns true if reused, false if fresh.
	 */
	checkAndRecordNonce(nonce: string): boolean {
		if (this.usedNonces.has(nonce)) return true;
		this.usedNonces.add(nonce);
		return false;
	}

	get(grantId: string): CapabilityGrant | null {
		return this.grants.get(grantId)?.grant ?? null;
	}

	/** Get the full stored token including signature metadata. */
	getStoredToken(grantId: string): StoredToken | null {
		return this.grants.get(grantId) ?? null;
	}

	validate(grantId: string): TokenValidation {
		const stored = this.grants.get(grantId);

		if (!stored) {
			return { valid: false, reason: `Grant not found: ${grantId}` };
		}

		const { grant } = stored;

		if (grant.revoked) {
			return { valid: false, reason: `Grant revoked: ${grantId}` };
		}

		const now = Date.now();
		const expiresAt = new Date(grant.lease.expiresAt).getTime();
		if (now > expiresAt) {
			return { valid: false, reason: `Grant expired at ${grant.lease.expiresAt}` };
		}

		if (grant.lease.callsUsed >= grant.lease.maxCalls) {
			return {
				valid: false,
				reason: `Grant exhausted: ${grant.lease.callsUsed}/${grant.lease.maxCalls} calls used`,
			};
		}

		return { valid: true };
	}

	/**
	 * Atomically validate and consume one use from a grant.
	 * Combines validation + increment in a single method to prevent
	 * TOCTOU race conditions where concurrent callers both pass
	 * validation before either increments callsUsed.
	 */
	consume(grantId: string): TokenValidation {
		const stored = this.grants.get(grantId);
		if (!stored) return { valid: false, reason: `Grant not found: ${grantId}` };

		const { grant } = stored;
		if (grant.revoked) return { valid: false, reason: `Grant revoked: ${grantId}` };

		const currentTime = Date.now();
		const expiresAt = new Date(grant.lease.expiresAt).getTime();
		if (currentTime > expiresAt) {
			return { valid: false, reason: `Grant expired at ${grant.lease.expiresAt}` };
		}
		if (grant.lease.callsUsed >= grant.lease.maxCalls) {
			return {
				valid: false,
				reason: `Grant exhausted: ${grant.lease.callsUsed}/${grant.lease.maxCalls} calls used`,
			};
		}

		// Atomically increment — no window between check and mutation
		grant.lease.callsUsed++;
		return { valid: true };
	}

	revoke(grantId: string): boolean {
		const stored = this.grants.get(grantId);
		if (!stored) return false;
		stored.grant.revoked = true;
		return true;
	}

	activeGrants(principalId: string): CapabilityGrant[] {
		const now = Date.now();
		return [...this.grants.values()]
			.filter(
				(s) =>
					s.grant.principalId === principalId &&
					!s.grant.revoked &&
					new Date(s.grant.lease.expiresAt).getTime() > now &&
					s.grant.lease.callsUsed < s.grant.lease.maxCalls,
			)
			.map((s) => s.grant);
	}
}
