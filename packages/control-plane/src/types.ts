import type { DecisionVerdict, PolicyRule, TaintLabel, ToolClass } from "@arikernel/core";

/**
 * Inbound decision request from sidecar → control plane.
 */
export interface DecisionRequest {
	/** Authenticated principal making the tool call. */
	principalId: string;
	/** Tool class: http, file, shell, database, retrieval, mcp */
	toolClass: ToolClass;
	/** The action to invoke (e.g. "GET", "read", "exec") */
	action: string;
	/** Tool-specific parameters */
	parameters: Record<string, unknown>;
	/** Taint labels from upstream data flow */
	taintLabels: TaintLabel[];
	/** Run identifier for cross-call correlation */
	runId: string;
	/** ISO 8601 timestamp of the request (used for freshness validation) */
	timestamp: string;
	/** Client-supplied nonce for request deduplication / replay protection */
	requestNonce?: string;
}

/**
 * Signed decision response from control plane → sidecar.
 */
export interface DecisionResponse {
	/** The enforcement verdict */
	decision: DecisionVerdict;
	/** Unique identifier for this decision */
	decisionId: string;
	/** Human-readable reason for the verdict */
	reason: string;
	/** Policy version used for this evaluation */
	policyVersion: string;
	/** SHA-256 prefix of the loaded policy ruleset */
	policyHash: string;
	/** Kernel build identifier */
	kernelBuild: string;
	/** ISO 8601 timestamp of the decision */
	timestamp: string;
	/** Cryptographic nonce for replay protection */
	nonce: string;
	/** Ed25519 signature over the canonical decision payload (hex-encoded) */
	signature: string;
	/** SHA-256 hash of the canonical request fields, binding this receipt to the original request */
	requestHash?: string;
	/** Echo of the client-supplied requestNonce, proving receipt freshness for this specific request */
	requestNonce?: string;
	/** The matched policy rule, if any */
	matchedRule?: PolicyRule;
	/** Taint labels forwarded through the decision */
	taintLabels: TaintLabel[];
}

/**
 * Request to register taint labels in the global registry.
 */
export interface TaintRegistrationRequest {
	/** Principal originating the taint */
	principalId: string;
	/** Run that produced the taint */
	runId: string;
	/** Labels to register */
	labels: TaintLabel[];
}

/**
 * Query for taint labels affecting a specific resource.
 */
export interface TaintQueryRequest {
	/** Resource identifier (e.g. file path, URL, database table) */
	resourceId: string;
}

export interface TaintQueryResponse {
	resourceId: string;
	labels: TaintLabel[];
}

/**
 * Control plane server configuration.
 */
export interface ControlPlaneConfig {
	/** TCP port to listen on. Default: 9090 */
	port?: number;
	/** Host to bind. Default: '127.0.0.1' */
	host?: string;
	/** Ed25519 signing key (hex-encoded 32-byte seed) for decision signatures */
	signingKey: string;
	/** Policy rules or path to policy file */
	policy?: string | PolicyRule[];
	/** Path for audit SQLite database. Default: ./control-plane-audit.db */
	auditLog?: string;
	/** Policy version label. Default: '1.0.0' */
	policyVersion?: string;
	/** Kernel build label. Default: 'arikernel-cp-0.1.0' */
	kernelBuild?: string;
	/** Bearer token for authenticating inbound requests from sidecars */
	authToken?: string;
}
