import { normalize, resolve } from "node:path";
import type { TaintLabel, ToolCallRequest } from "@arikernel/core";
import { now } from "@arikernel/core";

/**
 * Configuration for identifying which resources are shared between principals.
 * Only resources matching this config are tracked for cross-principal contamination.
 */
export interface SharedStoreConfig {
	/** File paths considered shared between agents (prefix match). */
	sharedStorePaths?: string[];
	/** Database names considered shared. */
	sharedDatabases?: string[];
	/** Table names considered shared. */
	sharedTables?: string[];
	/**
	 * TTL for contamination entries in milliseconds. After this duration,
	 * contamination is automatically expired and no longer returned by reads.
	 * Default: 3_600_000 (1 hour).
	 */
	contaminationTtlMs?: number;
	/**
	 * Maximum number of contamination entries. When exceeded, the oldest
	 * (least-recently-inserted) entry is evicted. Default: 10_000.
	 */
	maxContaminationEntries?: number;
}

/**
 * Canonicalize a resource key for consistent comparison.
 * - Database keys: lowercased table/database names
 * - File keys: NFKC-normalized, resolved, normalized paths
 */
function canonicalizeResourceKey(key: string): string {
	if (key.startsWith("db:")) {
		// Normalize database/table names to lowercase to prevent case-mismatch bypass
		return `db:${key.slice(3).normalize("NFKC").toLowerCase()}`;
	}
	if (key.startsWith("file:")) {
		const rawPath = key.slice(5);
		// NFKC normalization + resolve + normalize to collapse traversals and unicode tricks
		const normalized = rawPath.normalize("NFKC");
		const resolved = normalize(resolve(normalized));
		return `file:${resolved}`;
	}
	return key;
}

interface ContaminatedResource {
	key: string;
	principalId: string;
	timestamp: string;
	/** Epoch ms when this entry expires and should be evicted. */
	expiresAt: number;
}

/** DB actions that constitute a write for contamination marking. */
const DB_WRITE_ACTIONS = ["write", "insert", "update", "create", "exec", "mutate"];

/**
 * Build a database resource key that includes both database and table identity.
 * This prevents cross-database collisions where table names overlap.
 * Format: "db:<database>.<table>" or "db:<table>" if no database specified.
 */
function buildDbResourceKey(database: string | undefined, table: string): string {
	if (database) {
		return `db:${database}.${table}`;
	}
	return `db:${table}`;
}

/**
 * Tracks which shared resources have been written to by principals that
 * had previously read sensitive data. When another principal reads from
 * a contaminated resource, it receives a `derived-sensitive` taint label.
 *
 * Scope: lightweight provenance for shared stores, not full collusion prevention.
 */
export class SharedTaintRegistry {
	private readonly contaminated = new Map<string, ContaminatedResource>();
	private readonly config: SharedStoreConfig;
	private readonly ttlMs: number;
	private readonly maxEntries: number;

	constructor(config?: SharedStoreConfig) {
		this.config = config ?? {};
		this.ttlMs = this.config.contaminationTtlMs ?? 3_600_000; // 1 hour
		this.maxEntries = this.config.maxContaminationEntries ?? 10_000;
	}

	/** Mark a shared resource as contaminated by a principal. */
	markContaminated(key: string, principalId: string): void {
		const canonical = canonicalizeResourceKey(key);
		// Delete first so re-insert moves it to end of Map iteration order (LRU refresh)
		this.contaminated.delete(canonical);
		this.contaminated.set(canonical, {
			key: canonical,
			principalId,
			timestamp: now(),
			expiresAt: Date.now() + this.ttlMs,
		});
		this.evictOverflow();
	}

	/** Check if a shared resource has been contaminated (not expired). */
	isContaminated(key: string): boolean {
		const canonical = canonicalizeResourceKey(key);
		const entry = this.contaminated.get(canonical);
		if (!entry) return false;
		if (Date.now() >= entry.expiresAt) {
			this.contaminated.delete(canonical);
			return false;
		}
		return true;
	}

	/** Get contamination metadata for a resource (not expired). */
	getContamination(key: string): ContaminatedResource | undefined {
		const canonical = canonicalizeResourceKey(key);
		const entry = this.contaminated.get(canonical);
		if (!entry) return undefined;
		if (Date.now() >= entry.expiresAt) {
			this.contaminated.delete(canonical);
			return undefined;
		}
		return entry;
	}

	/** Evict oldest entries when map exceeds maxEntries. */
	private evictOverflow(): void {
		while (this.contaminated.size > this.maxEntries) {
			// Map iteration order = insertion order; first key is oldest
			const oldest = this.contaminated.keys().next().value;
			if (oldest !== undefined) {
				this.contaminated.delete(oldest);
			} else {
				break;
			}
		}
	}

	/**
	 * Extract a resource key from a tool call, returning null if the resource
	 * is not a configured shared resource or the action is not relevant.
	 */
	extractResourceKey(
		toolClass: string,
		action: string,
		params: Record<string, unknown>,
	): string | null {
		if (toolClass === "database" && DB_WRITE_ACTIONS.includes(action)) {
			const table = params.table as string | undefined;
			if (!table) return null;
			const db = params.database as string | undefined;
			const dbKey = buildDbResourceKey(db, table);
			const normalizedTable = table.normalize("NFKC").toLowerCase();
			if (this.config.sharedTables?.some((t) => t.toLowerCase() === normalizedTable)) {
				return canonicalizeResourceKey(dbKey);
			}
			if (
				db &&
				this.config.sharedDatabases?.some(
					(d) => d.toLowerCase() === db.normalize("NFKC").toLowerCase(),
				)
			) {
				return canonicalizeResourceKey(dbKey);
			}
			return null;
		}

		if (toolClass === "database" && action === "query") {
			const table = params.table as string | undefined;
			if (!table) return null;
			const db = params.database as string | undefined;
			const dbKey = buildDbResourceKey(db, table);
			const normalizedTable = table.normalize("NFKC").toLowerCase();
			if (this.config.sharedTables?.some((t) => t.toLowerCase() === normalizedTable)) {
				return canonicalizeResourceKey(dbKey);
			}
			if (
				db &&
				this.config.sharedDatabases?.some(
					(d) => d.toLowerCase() === db.normalize("NFKC").toLowerCase(),
				)
			) {
				return canonicalizeResourceKey(dbKey);
			}
			return null;
		}

		if (toolClass === "file" && action === "write") {
			const filePath = params.path as string | undefined;
			if (!filePath) return null;
			if (this.isSharedPath(filePath)) return canonicalizeResourceKey(`file:${filePath}`);
			return null;
		}

		if (toolClass === "file" && action === "read") {
			const filePath = params.path as string | undefined;
			if (!filePath) return null;
			if (this.isSharedPath(filePath)) return canonicalizeResourceKey(`file:${filePath}`);
			return null;
		}

		return null;
	}

	/** Check if a file path matches any configured shared store path prefix. */
	private isSharedPath(filePath: string): boolean {
		if (!this.config.sharedStorePaths) return false;
		const normalizedPath = normalize(resolve(filePath.normalize("NFKC")));
		return this.config.sharedStorePaths.some((prefix) => {
			const normalizedPrefix = normalize(resolve(prefix.normalize("NFKC")));
			const sep = process.platform === "win32" ? "\\" : "/";
			return (
				normalizedPath === normalizedPrefix || normalizedPath.startsWith(normalizedPrefix + sep)
			);
		});
	}

	/**
	 * Create a `derived-sensitive` taint label for injection into a reading principal.
	 */
	static createDerivedSensitiveTaint(originPrincipal: string): TaintLabel {
		return {
			source: "derived-sensitive",
			origin: `cross-principal:${originPrincipal}`,
			confidence: 0.8,
			addedAt: now(),
			propagatedFrom: originPrincipal,
		};
	}
}
