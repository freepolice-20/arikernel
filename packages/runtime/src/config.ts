import type { Capability, PolicyRule, SigningKey } from "@arikernel/core";
import { firewallConfigSchema } from "@arikernel/core";
import type { FirewallHooks } from "./hooks.js";
import type { RunStatePolicy } from "./run-state.js";

/**
 * Security mode controls whether capability tokens are required.
 * - 'dev': tokens are optional (backward compatible, no signing key needed)
 * - 'secure': tokens are required and must be cryptographically signed
 */
export type SecurityMode = "dev" | "secure";

/**
 * Enforcement mode determines where tool execution actually happens.
 *
 * - `"embedded"` (default): Tools execute in-process. The host has direct
 *   access to executors. Security is cooperative — the host could bypass
 *   the pipeline. Suitable for trusted environments or development.
 *
 * - `"sidecar"`: Tools execute only via the sidecar HTTP API. The host
 *   process has no direct access to real executors — all execution is
 *   delegated through SidecarProxyExecutors. The sidecar is the
 *   authoritative enforcement boundary. Recommended for production.
 */
export type EnforcementMode = "embedded" | "sidecar";

export interface SidecarConnectionOptions {
	/** Base URL of the sidecar server. Default: http://localhost:8787 */
	baseUrl?: string;
	/** principalId for sidecar calls. Defaults to principal.name. */
	principalId?: string;
	/** Bearer token for sidecar authentication. */
	authToken?: string;
}

export interface FirewallOptions {
	principal: {
		name: string;
		capabilities: Capability[];
	};
	policies: string | PolicyRule[];
	auditLog?: string;
	hooks?: FirewallHooks;
	runStatePolicy?: RunStatePolicy;
	/** Optional signing key for cryptographically signed capability tokens. */
	signingKey?: SigningKey;
	/**
	 * Security mode. Default: 'dev' if no signingKey, 'secure' if signingKey is provided.
	 * In 'secure' mode, all tool invocations require a valid signed capability token.
	 * In 'dev' mode, tokens are optional for backward compatibility.
	 */
	securityMode?: SecurityMode;
	/**
	 * Enforcement mode. Default: "embedded".
	 *
	 * In "sidecar" mode, all tool execution is delegated to the sidecar
	 * HTTP server. The host process cannot execute tools directly.
	 * `sidecar` connection options must be provided when using this mode.
	 */
	mode?: EnforcementMode;
	/** Sidecar connection config. Required when mode is "sidecar". */
	sidecar?: SidecarConnectionOptions;
}

export function validateOptions(options: FirewallOptions): FirewallOptions {
	firewallConfigSchema.parse({
		principal: options.principal,
		policies: options.policies,
		auditLog: options.auditLog ?? "./audit.db",
	});
	return options;
}
