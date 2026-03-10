import type { CapabilityGrant } from "@arikernel/core";

export interface TokenValidation {
	valid: boolean;
	reason?: string;
}

export class TokenStore {
	private grants = new Map<string, CapabilityGrant>();

	store(grant: CapabilityGrant): void {
		this.grants.set(grant.id, grant);
	}

	get(grantId: string): CapabilityGrant | null {
		return this.grants.get(grantId) ?? null;
	}

	validate(grantId: string): TokenValidation {
		const grant = this.grants.get(grantId);

		if (!grant) {
			return { valid: false, reason: `Grant not found: ${grantId}` };
		}

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
		const grant = this.grants.get(grantId);
		if (!grant) return { valid: false, reason: `Grant not found: ${grantId}` };
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
		const grant = this.grants.get(grantId);
		if (!grant) return false;
		grant.revoked = true;
		return true;
	}

	activeGrants(principalId: string): CapabilityGrant[] {
		const now = Date.now();
		return [...this.grants.values()].filter(
			(g) =>
				g.principalId === principalId &&
				!g.revoked &&
				new Date(g.lease.expiresAt).getTime() > now &&
				g.lease.callsUsed < g.lease.maxCalls,
		);
	}
}
