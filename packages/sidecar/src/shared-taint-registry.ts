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

	constructor(config?: SharedStoreConfig) {
		this.config = config ?? {};
	}

	/** Mark a shared resource as contaminated by a principal. */
	markContaminated(key: string, principalId: string): void {
		const canonical = canonicalizeResourceKey(key);
		this.contaminated.set(canonical, {
			key: canonical,
			principalId,
			timestamp: now(),
		});
	}

	/** Check if a shared resource has been contaminated. */
	isContaminated(key: string): boolean {
		return this.contaminated.has(canonicalizeResourceKey(key));
	}

	/** Get contamination metadata for a resource. */
	getContamination(key: string): ContaminatedResource | undefined {
		return this.contaminated.get(canonicalizeResourceKey(key));
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
