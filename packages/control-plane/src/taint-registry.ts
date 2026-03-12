import type { TaintLabel } from "@arikernel/core";
import type { ControlPlaneAuditStore } from "./audit-store.js";

/**
 * Global taint registry for cross-agent, cross-run taint correlation.
 *
 * Tracks taint labels by resource (file path, URL, database table) and by
 * principal/run. This allows the control plane to detect when Agent A
 * contaminates a shared resource that Agent B later reads.
 *
 * When an audit store is injected, taint entries are persisted to SQLite
 * and reloaded on construction so that taint state survives process restarts.
 */
export class GlobalTaintRegistry {
	/** resource → taint labels */
	private readonly byResource = new Map<string, TaintLabel[]>();
	/** principalId:runId → taint labels */
	private readonly byPrincipalRun = new Map<string, TaintLabel[]>();
	private readonly auditStore: ControlPlaneAuditStore | undefined;

	constructor(auditStore?: ControlPlaneAuditStore) {
		this.auditStore = auditStore;
		if (auditStore) {
			this.reloadFromStore(auditStore);
		}
	}

	/**
	 * Register taint labels for a principal's run.
	 * Also associates labels with any resource identifiers found in the parameters.
	 */
	register(principalId: string, runId: string, labels: TaintLabel[], resourceIds?: string[]): void {
		if (labels.length === 0) return;

		const runKey = `${principalId}:${runId}`;
		const existing = this.byPrincipalRun.get(runKey) ?? [];
		this.byPrincipalRun.set(runKey, dedup([...existing, ...labels]));

		// Persist run-level taint entries
		if (this.auditStore) {
			for (const label of labels) {
				this.auditStore.recordTaintEvent(principalId, runId, label.source, label.origin, null);
			}
		}

		if (resourceIds) {
			for (const resourceId of resourceIds) {
				const resourceLabels = this.byResource.get(resourceId) ?? [];
				this.byResource.set(resourceId, dedup([...resourceLabels, ...labels]));

				// Persist resource-level taint entries
				if (this.auditStore) {
					for (const label of labels) {
						this.auditStore.recordTaintEvent(
							principalId,
							runId,
							label.source,
							label.origin,
							resourceId,
						);
					}
				}
			}
		}
	}

	/**
	 * Query taint labels for a specific resource.
	 */
	queryResource(resourceId: string): TaintLabel[] {
		return this.byResource.get(resourceId) ?? [];
	}

	/**
	 * Query taint labels for a principal's run.
	 */
	queryRun(principalId: string, runId: string): TaintLabel[] {
		return this.byPrincipalRun.get(`${principalId}:${runId}`) ?? [];
	}

	/**
	 * Get all taint labels across all resources and runs.
	 */
	allResources(): ReadonlyMap<string, TaintLabel[]> {
		return this.byResource;
	}

	get resourceCount(): number {
		return this.byResource.size;
	}

	get runCount(): number {
		return this.byPrincipalRun.size;
	}

	// ── Private helpers ───────────────────────────────────────────────

	private reloadFromStore(store: ControlPlaneAuditStore): void {
		const rows = store.allTaintEvents();
		for (const row of rows) {
			const label: TaintLabel = {
				source: row.label_source as TaintLabel["source"],
				origin: row.label_origin,
				confidence: 1.0,
				addedAt: row.timestamp,
			};

			// Reload run-level taint
			const runKey = `${row.principal_id}:${row.run_id}`;
			const runLabels = this.byPrincipalRun.get(runKey) ?? [];
			this.byPrincipalRun.set(runKey, dedup([...runLabels, label]));

			// Reload resource-level taint
			if (row.resource_id) {
				const resourceLabels = this.byResource.get(row.resource_id) ?? [];
				this.byResource.set(row.resource_id, dedup([...resourceLabels, label]));
			}
		}
	}
}

/**
 * Deduplicate taint labels by source:origin key.
 */
function dedup(labels: TaintLabel[]): TaintLabel[] {
	const seen = new Set<string>();
	const result: TaintLabel[] = [];
	for (const label of labels) {
		const key = `${label.source}:${label.origin}`;
		if (!seen.has(key)) {
			seen.add(key);
			result.push(label);
		}
	}
	return result;
}
