import type { Capability, PolicyRule, SigningKey } from "@arikernel/core";
import { firewallConfigSchema } from "@arikernel/core";
import type { FirewallHooks } from "./hooks.js";
import type { PersistentTaintConfig } from "./persistent-taint-registry.js";
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
 * - `"sidecar"` (recommended for production): Tools execute only via the
 *   sidecar HTTP API. The host process has no direct access to real
 *   executors — all execution is delegated through SidecarProxyExecutors.
 *   The sidecar is the authoritative enforcement boundary.
 *
 * - `"embedded"`: Tools execute in-process. Security is cooperative —
 *   the host could bypass the pipeline. Suitable for development or
 *   trusted environments only. Must be set explicitly.
 *
 * **Mode must be set explicitly.** Omitting it in production throws a
 * startup error. In non-production, omitting it warns and defaults to
 * `"embedded"` for backward compatibility.
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
	 * Enforcement mode. **Must be set explicitly in production.**
	 *
	 * - `"sidecar"` (recommended): delegates all tool execution to the
	 *   sidecar HTTP server. Requires `sidecar` connection options.
	 * - `"embedded"`: runs tools in-process. Suitable for development
	 *   or trusted environments only.
	 *
	 * Omitting this field in production throws a startup error.
	 * In non-production it defaults to `"embedded"` with a warning.
	 */
	mode?: EnforcementMode;
	/**
	 * Sidecar connection config. Required when mode is `"sidecar"`.
	 * Defaults: baseUrl = http://localhost:8787, principalId = principal.name.
	 */
	sidecar?: SidecarConnectionOptions;
	/**
	 * Persistent taint tracking across runs for the same principal.
	 * When enabled, sticky flags (sensitiveReadObserved, secretAccessObserved, etc.)
	 * survive across run boundaries, preventing attackers from splitting attacks
	 * across multiple runs.
	 */
	persistentTaint?: PersistentTaintConfig;
}

export function validateOptions(options: FirewallOptions): FirewallOptions {
	firewallConfigSchema.parse({
		principal: options.principal,
		policies: options.policies,
		auditLog: options.auditLog ?? "./audit.db",
	});
	return options;
}
