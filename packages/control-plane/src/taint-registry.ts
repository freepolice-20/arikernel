import type { TaintLabel } from "@arikernel/core";

/**
 * Global taint registry for cross-agent, cross-run taint correlation.
 *
 * Tracks taint labels by resource (file path, URL, database table) and by
 * principal/run. This allows the control plane to detect when Agent A
 * contaminates a shared resource that Agent B later reads.
 */
export class GlobalTaintRegistry {
	/** resource → taint labels */
	private readonly byResource = new Map<string, TaintLabel[]>();
	/** principalId:runId → taint labels */
	private readonly byPrincipalRun = new Map<string, TaintLabel[]>();

	/**
	 * Register taint labels for a principal's run.
	 * Also associates labels with any resource identifiers found in the parameters.
	 */
	register(
		principalId: string,
		runId: string,
		labels: TaintLabel[],
		resourceIds?: string[],
	): void {
		if (labels.length === 0) return;

		const runKey = `${principalId}:${runId}`;
		const existing = this.byPrincipalRun.get(runKey) ?? [];
		this.byPrincipalRun.set(runKey, dedup([...existing, ...labels]));

		if (resourceIds) {
			for (const resourceId of resourceIds) {
				const resourceLabels = this.byResource.get(resourceId) ?? [];
				this.byResource.set(resourceId, dedup([...resourceLabels, ...labels]));
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
