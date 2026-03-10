import type { TaintLabel, ToolClass } from "@arikernel/core";

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
	/**
	 * Host/IP to bind to. Default: '127.0.0.1' (localhost only).
	 * Set to '0.0.0.0' to listen on all interfaces (requires explicit opt-in).
	 */
	host?: string;
	/**
	 * Path to policy file, or inline rules array.
	 * Required unless `preset` is provided.
	 */
	policy?: string | import("@arikernel/core").PolicyRule[];
	/** Path for the audit SQLite database. Default: ./sidecar-audit.db */
	auditLog?: string;
	/** Run-state policy options. Overrides preset defaults when both are set. */
	runStatePolicy?: import("@arikernel/runtime").RunStatePolicy;
	/**
	 * Shared secret for authenticating requests. When set, all requests must
	 * include an `Authorization: Bearer <token>` header matching this value.
	 * Strongly recommended for any non-localhost deployment.
	 */
	authToken?: string;
	/**
	 * Named preset: "safe", "strict", "research", "safe-research",
	 * "rag-reader", "workspace-assistant", "automation-agent".
	 * Provides pre-configured policies, capabilities, and run-state rules.
	 * When set, `policy` and `capabilities` are optional (preset values used).
	 * Explicit `policy` / `capabilities` override preset defaults.
	 */
	preset?: import("@arikernel/core").PresetId;
	/**
	 * Per-principal capabilities. When set, each principal receives these
	 * constrained capabilities instead of unconstrained defaults.
	 * Overrides preset capabilities when both are set.
	 */
	capabilities?: import("@arikernel/core").Capability[];
}
