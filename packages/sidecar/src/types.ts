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
	/**
	 * Grant ID from a prior /request-capability call.
	 * When provided, the sidecar uses this existing grant instead of
	 * auto-issuing a new one. Takes precedence over server auto-issue
	 * but is overridden by capabilityToken.
	 */
	grantId?: string;
	/**
	 * Serialized signed capability token (base64-encoded).
	 * When the sidecar is in 'secure' mode, this token is verified
	 * independently before execution. In 'dev' mode, the sidecar
	 * auto-issues tokens server-side.
	 * Takes highest precedence: capabilityToken > grantId > auto-issue.
	 */
	capabilityToken?: string;
}

export interface ExecuteResponse {
	/** Whether the action was permitted by policy. false = security denial. */
	allowed: boolean;
	/**
	 * Whether the tool execution succeeded. Only meaningful when allowed=true.
	 * false means the tool ran but encountered an operational error (e.g. file
	 * not found, HTTP 404). This is NOT a security denial — it should not
	 * increment denied-action counters or trigger quarantine.
	 */
	success?: boolean;
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

export interface RequestCapabilityRequest {
	/** Who is requesting the capability. */
	principalId: string;
	/** The capability class to request (e.g. "http.write", "file.read"). */
	capabilityClass: string;
	/** Optional constraints to narrow the grant. */
	constraints?: import("@arikernel/core").CapabilityConstraint;
	/** Optional justification for the request. */
	justification?: string;
}

export interface RequestCapabilityResponse {
	granted: boolean;
	/** Grant ID to use in subsequent execute calls. */
	grantId?: string;
	/** Serialized signed capability token (base64). Present when signing is enabled. */
	capabilityToken?: string;
	reason?: string;
}

/**
 * Maps API keys to principal identities. When configured, the sidecar derives
 * principalId from the Bearer token rather than trusting client-supplied values.
 * Key: API key string. Value: principal configuration.
 */
export interface PrincipalCredentials {
	[apiKey: string]: { principalId: string };
}

/**
 * Rate limiting and admission control configuration.
 */
export interface RateLimitConfig {
	/** Max firewall instances per principal. Default: unlimited. */
	maxFirewallsPerPrincipal?: number;
	/** Max concurrent tool executions per principal. Default: unlimited. */
	maxConcurrentExecutions?: number;
	/** Max requests per second per principal (sliding window). Default: unlimited. */
	maxRequestsPerSecond?: number;
	/** Max total firewall instances across all principals. Default: unlimited. */
	globalMaxFirewalls?: number;
	/** Max total concurrent executions across all principals. Default: unlimited. */
	globalMaxConcurrentExecutions?: number;
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
	 *
	 * In dev mode (no `principals` configured), this is a shared secret.
	 * When `principals` is configured, `authToken` is ignored — each principal
	 * authenticates with their own API key.
	 */
	authToken?: string;
	/**
	 * Per-principal API key → identity mapping. When set, the sidecar derives
	 * principalId from the Bearer token (API key) rather than trusting
	 * client-supplied values. This is the recommended production configuration.
	 *
	 * When not set, the sidecar operates in "dev mode" where clients supply
	 * their own principalId in the request body.
	 */
	principals?: PrincipalCredentials;
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
	/**
	 * Signing key for cryptographic capability token verification.
	 * When set, the sidecar operates in 'secure' mode: all capability tokens
	 * are signed and verified before tool execution.
	 */
	signingKey?: import("@arikernel/core").SigningKey;
	/**
	 * Security mode override. Default: 'secure' if signingKey provided, 'dev' otherwise.
	 */
	securityMode?: import("@arikernel/runtime").SecurityMode;
	/**
	 * Rate limiting and admission control. When set, enforces per-principal
	 * and global limits on firewall instances, concurrent executions, and
	 * request rates.
	 */
	rateLimits?: RateLimitConfig;
	/**
	 * Shared store configuration for cross-principal taint tracking.
	 * Identifies which file paths, databases, and tables are shared between principals.
	 */
	sharedStoreConfig?: import("./shared-taint-registry.js").SharedStoreConfig;
	/**
	 * Cross-principal correlator configuration.
	 */
	correlatorConfig?: import("./correlator.js").CorrelatorConfig;
	/**
	 * Callback fired when the cross-principal correlator detects a suspicious pattern.
	 * Alerting only — does not block execution.
	 */
	onCrossPrincipalAlert?: import("./correlator.js").AlertHandler;
	/**
	 * Decision mode: 'local' (default) evaluates policies in-process,
	 * 'remote' delegates policy decisions to a control plane service.
	 */
	decisionMode?: import("./decision-delegate.js").DecisionMode;
	/**
	 * Control plane base URL. Required when decisionMode is 'remote'.
	 * Example: 'http://localhost:9090'
	 */
	controlPlaneUrl?: string;
	/**
	 * Bearer token for authenticating with the control plane.
	 */
	controlPlaneAuthToken?: string;
	/**
	 * Timeout in milliseconds for control plane requests. Default: 5000.
	 * If the control plane is unreachable within this window, the sidecar
	 * fails closed (denies the request).
	 */
	controlPlaneTimeoutMs?: number;
	/**
	 * Path to TLS certificate file (PEM format). When both tlsCert and
	 * tlsKey are provided, the sidecar serves HTTPS instead of HTTP.
	 */
	tlsCert?: string;
	/**
	 * Path to TLS private key file (PEM format). Required when tlsCert
	 * is provided.
	 */
	tlsKey?: string;
}
