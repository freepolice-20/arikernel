import type { TaintLabel, ToolClass } from '@arikernel/core';

export interface ExecuteRequest {
	/** Who is making the call. Resolved to a sidecar-managed principal. */
	principalId: string;
	/** Tool class: http, file, shell, database, retrieval, mcp */
	toolClass: ToolClass;
	/** The action to invoke (e.g. "GET", "read", "exec", "query") */
	action: string;
	/** Tool-specific parameters */
	params: Record<string, unknown>;
	/** Upstream taint labels to attach to the call */
	taint?: TaintLabel[];
}

export interface ExecuteResponse {
	allowed: boolean;
	/** Result data when allowed and execution succeeded */
	result?: unknown;
	/** Error message when denied or execution failed */
	error?: string;
	/** Taint labels on the result (propagated from executor auto-taints) */
	resultTaint?: TaintLabel[];
	/** The internal AriKernel call ID for correlation */
	callId?: string;
}

export interface StatusResponse {
	principalId: string;
	restricted: boolean;
	runId: string;
	/** Denial and behavioral counters for this principal's run */
	counters: {
		deniedActions: number;
		capabilityRequests: number;
		sensitiveFileReadAttempts: number;
		externalEgressAttempts: number;
	};
	/** Quarantine info if restricted */
	quarantine?: {
		reason: string;
		triggerType: string;
		timestamp: string;
	};
}

export interface SidecarConfig {
	/** TCP port to listen on. Default: 8787 */
	port?: number;
	/** Path to policy file, or inline rules array. Required. */
	policy: string | import('@arikernel/core').PolicyRule[];
	/** Path for the audit SQLite database. Default: ./sidecar-audit.db */
	auditLog?: string;
	/** Run-state policy options */
	runStatePolicy?: import('@arikernel/runtime').RunStatePolicy;
}
