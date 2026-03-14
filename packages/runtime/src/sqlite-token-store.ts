import type { CapabilityGrant, SigningAlgorithm } from "@arikernel/core";
import Database from "better-sqlite3";
import type { ITokenStore, StoredToken, TokenValidation } from "./token-store.js";

/**
 * SQLite-backed persistent TokenStore.
 *
 * Grants survive sidecar restarts — agents don't lose mid-workflow
 * capabilities when the sidecar is restarted or redeployed.
 *
 * Uses better-sqlite3 (synchronous) for consistency with AuditStore.
 * LRU eviction and TTL expiry match the in-memory TokenStore behavior.
 */
export class SqliteTokenStore implements ITokenStore {
	private readonly db: Database.Database;
	private readonly maxSize: number;

	private readonly stmtUpsert: Database.Statement;
	private readonly stmtGet: Database.Statement;
	private readonly stmtDelete: Database.Statement;
	private readonly stmtRevoke: Database.Statement;
	private readonly stmtCount: Database.Statement;
	private readonly stmtEvictExpired: Database.Statement;
	private readonly stmtEvictOldest: Database.Statement;
	private readonly stmtActiveGrants: Database.Statement;
	private readonly stmtTouch: Database.Statement;
	private readonly stmtIncrementCalls: Database.Statement;

	constructor(dbPath: string, options?: { maxSize?: number }) {
		this.db = new Database(dbPath);
		this.maxSize = options?.maxSize ?? 10_000;

		this.db.pragma("journal_mode = WAL");
		this.db.pragma("busy_timeout = 5000");

		this.db.exec(`
			CREATE TABLE IF NOT EXISTS grants (
				id TEXT PRIMARY KEY,
				principal_id TEXT NOT NULL,
				data TEXT NOT NULL,
				signature TEXT,
				algorithm TEXT,
				last_accessed INTEGER NOT NULL DEFAULT (unixepoch('now','subsec') * 1000)
			)
		`);

		this.stmtUpsert = this.db.prepare(`
			INSERT OR REPLACE INTO grants (id, principal_id, data, signature, algorithm, last_accessed)
			VALUES (?, ?, ?, ?, ?, ?)
		`);

		this.stmtGet = this.db.prepare(`
			SELECT data, signature, algorithm FROM grants WHERE id = ?
		`);

		this.stmtDelete = this.db.prepare(`DELETE FROM grants WHERE id = ?`);

		this.stmtRevoke = this.db.prepare(`
			UPDATE grants SET data = json_set(data, '$.revoked', json('true'))
			WHERE id = ?
		`);

		this.stmtCount = this.db.prepare(`SELECT COUNT(*) as cnt FROM grants`);

		this.stmtEvictExpired = this.db.prepare(`
			DELETE FROM grants WHERE
				json_extract(data, '$.revoked') = 1
				OR json_extract(data, '$.lease.callsUsed') >= json_extract(data, '$.lease.maxCalls')
				OR json_extract(data, '$.lease.expiresAt') <= ?
		`);

		this.stmtEvictOldest = this.db.prepare(`
			DELETE FROM grants WHERE id IN (
				SELECT id FROM grants ORDER BY last_accessed ASC LIMIT ?
			)
		`);

		this.stmtActiveGrants = this.db.prepare(`
			SELECT data, signature, algorithm FROM grants
			WHERE principal_id = ?
			AND json_extract(data, '$.revoked') IS NOT 1
			AND json_extract(data, '$.lease.callsUsed') < json_extract(data, '$.lease.maxCalls')
		`);

		this.stmtTouch = this.db.prepare(`
			UPDATE grants SET last_accessed = ? WHERE id = ?
		`);

		this.stmtIncrementCalls = this.db.prepare(`
			UPDATE grants SET
				data = json_set(data, '$.lease.callsUsed', json_extract(data, '$.lease.callsUsed') + 1),
				last_accessed = ?
			WHERE id = ?
		`);
	}

	store(grant: CapabilityGrant, signature?: string, algorithm?: SigningAlgorithm): void {
		this.stmtUpsert.run(
			grant.id,
			grant.principalId,
			JSON.stringify(grant),
			signature ?? null,
			algorithm ?? null,
			Date.now(),
		);
		this.enforceMaxSize();
	}

	private enforceMaxSize(): void {
		const { cnt } = this.stmtCount.get() as { cnt: number };
		if (cnt <= this.maxSize) return;

		this.evictExpired();
		const after = (this.stmtCount.get() as { cnt: number }).cnt;
		if (after > this.maxSize) {
			this.stmtEvictOldest.run(after - this.maxSize);
		}
	}

	evictExpired(): number {
		const result = this.stmtEvictExpired.run(new Date().toISOString());
		return result.changes;
	}

	get(grantId: string): CapabilityGrant | null {
		const row = this.stmtGet.get(grantId) as
			| { data: string; signature: string | null; algorithm: string | null }
			| undefined;
		if (!row) return null;
		// LRU touch
		this.stmtTouch.run(Date.now(), grantId);
		return JSON.parse(row.data) as CapabilityGrant;
	}

	getStoredToken(grantId: string): StoredToken | null {
		const row = this.stmtGet.get(grantId) as
			| { data: string; signature: string | null; algorithm: string | null }
			| undefined;
		if (!row) return null;
		// LRU touch
		this.stmtTouch.run(Date.now(), grantId);
		return {
			grant: JSON.parse(row.data) as CapabilityGrant,
			signature: row.signature ?? undefined,
			algorithm: (row.algorithm as SigningAlgorithm) ?? undefined,
		};
	}

	validate(grantId: string): TokenValidation {
		const row = this.stmtGet.get(grantId) as { data: string } | undefined;
		if (!row) return { valid: false, reason: `Grant not found: ${grantId}` };

		const grant = JSON.parse(row.data) as CapabilityGrant;

		if (grant.revoked) return { valid: false, reason: `Grant revoked: ${grantId}` };

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

	consume(grantId: string): TokenValidation {
		const validation = this.validate(grantId);
		if (!validation.valid) return validation;

		// Atomically increment callsUsed + LRU touch in a single UPDATE
		this.stmtIncrementCalls.run(Date.now(), grantId);
		return { valid: true };
	}

	revoke(grantId: string): boolean {
		const result = this.stmtRevoke.run(grantId);
		return result.changes > 0;
	}

	activeGrants(principalId: string): CapabilityGrant[] {
		const now = Date.now();
		const rows = this.stmtActiveGrants.all(principalId) as Array<{
			data: string;
			signature: string | null;
			algorithm: string | null;
		}>;
		return rows
			.map((r) => JSON.parse(r.data) as CapabilityGrant)
			.filter((g) => new Date(g.lease.expiresAt).getTime() > now);
	}

	close(): void {
		this.db.close();
	}
}
