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

/**
 * Common interface for token stores. Both the in-memory TokenStore and
 * the SQLite-backed SqliteTokenStore implement this interface.
 *
 * **Multi-instance scope:** Grant consumption (`consume()`) is atomic within
 * a single ITokenStore instance. In horizontally scaled deployments where
 * multiple sidecar replicas each have their own store, the same signed grant
 * can be consumed independently on each replica (double-spend). To prevent
 * this, back all replicas with a shared ITokenStore implementation (shared
 * SQLite WAL file, Redis, Postgres) so that `consume()` is globally atomic.
 * Revocation has the same scope — `revoke()` on one store does not propagate
 * to independent stores.
 */
export interface ITokenStore {
	store(grant: CapabilityGrant, signature?: string, algorithm?: SigningAlgorithm): void;
	evictExpired(): number;
	get(grantId: string): CapabilityGrant | null;
	getStoredToken(grantId: string): StoredToken | null;
	validate(grantId: string): TokenValidation;
	consume(grantId: string): TokenValidation;
	revoke(grantId: string): boolean;
	activeGrants(principalId: string): CapabilityGrant[];
}

export class TokenStore implements ITokenStore {
	private grants = new Map<string, StoredToken>();

	/**
	 * Hard upper bound on stored grants. When exceeded after evicting
	 * expired/revoked/exhausted entries, the oldest active grants are
	 * evicted (LRU order). Default: 10_000.
	 */
	private readonly maxSize: number;

	constructor(options?: { maxSize?: number }) {
		this.maxSize = options?.maxSize ?? 10_000;
	}

	store(grant: CapabilityGrant, signature?: string, algorithm?: SigningAlgorithm): void {
		// Delete first so re-insert moves to end of Map order (LRU refresh)
		this.grants.delete(grant.id);
		this.grants.set(grant.id, { grant, signature, algorithm });
		this.enforceMaxSize();
	}

	/** Enforce maxSize: evict expired first, then oldest active if still over. */
	private enforceMaxSize(): void {
		if (this.grants.size <= this.maxSize) return;
		this.evictExpired();
		// If still over after removing dead entries, evict oldest active (LRU)
		while (this.grants.size > this.maxSize) {
			const oldest = this.grants.keys().next().value;
			if (oldest !== undefined) {
				this.grants.delete(oldest);
			} else {
				break;
			}
		}
	}

	/** Remove all expired, exhausted, or revoked grants. Returns count removed. */
	evictExpired(): number {
		const now = Date.now();
		let removed = 0;
		for (const [id, stored] of this.grants) {
			const { grant } = stored;
			if (
				grant.revoked ||
				new Date(grant.lease.expiresAt).getTime() <= now ||
				grant.lease.callsUsed >= grant.lease.maxCalls
			) {
				this.grants.delete(id);
				removed++;
			}
		}
		return removed;
	}

	get(grantId: string): CapabilityGrant | null {
		const stored = this.grants.get(grantId);
		if (!stored) return null;
		// LRU touch: move to end of iteration order
		this.grants.delete(grantId);
		this.grants.set(grantId, stored);
		return stored.grant;
	}

	/** Get the full stored token including signature metadata. */
	getStoredToken(grantId: string): StoredToken | null {
		const stored = this.grants.get(grantId);
		if (!stored) return null;
		// LRU touch: move to end of iteration order
		this.grants.delete(grantId);
		this.grants.set(grantId, stored);
		return stored;
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

		// LRU touch: move to end of iteration order
		this.grants.delete(grantId);
		this.grants.set(grantId, stored);

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
