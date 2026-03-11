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

interface ContaminatedResource {
	key: string;
	principalId: string;
	timestamp: string;
}

/** DB actions that constitute a write for contamination marking. */
const DB_WRITE_ACTIONS = ["write", "insert", "update", "create", "exec", "mutate"];

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
		this.contaminated.set(key, {
			key,
			principalId,
			timestamp: now(),
		});
	}

	/** Check if a shared resource has been contaminated. */
	isContaminated(key: string): boolean {
		return this.contaminated.has(key);
	}

	/** Get contamination metadata for a resource. */
	getContamination(key: string): ContaminatedResource | undefined {
		return this.contaminated.get(key);
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
			// Check if this DB or table is configured as shared
			if (this.config.sharedTables?.includes(table)) return `db:${table}`;
			if (db && this.config.sharedDatabases?.includes(db)) return `db:${table}`;
			return null;
		}

		if (toolClass === "database" && action === "query") {
			const table = params.table as string | undefined;
			if (!table) return null;
			const db = params.database as string | undefined;
			if (this.config.sharedTables?.includes(table)) return `db:${table}`;
			if (db && this.config.sharedDatabases?.includes(db)) return `db:${table}`;
			return null;
		}

		if (toolClass === "file" && action === "write") {
			const path = params.path as string | undefined;
			if (!path) return null;
			if (this.isSharedPath(path)) return `file:${path}`;
			return null;
		}

		if (toolClass === "file" && action === "read") {
			const path = params.path as string | undefined;
			if (!path) return null;
			if (this.isSharedPath(path)) return `file:${path}`;
			return null;
		}

		return null;
	}

	/** Check if a file path matches any configured shared store path prefix. */
	private isSharedPath(path: string): boolean {
		if (!this.config.sharedStorePaths) return false;
		return this.config.sharedStorePaths.some(
			(prefix) => path === prefix || path.startsWith(prefix.endsWith("/") ? prefix : prefix + "/"),
		);
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
