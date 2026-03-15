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
 * Enforcement mode determines where policy evaluation and tool execution happen.
 *
 * - `"sidecar"` (recommended for production): The host Firewall acts as a
 *   **thin client**. All policy evaluation, token management, behavioral
 *   rules, taint tracking, and tool execution are delegated to the sidecar
 *   HTTP server. The host performs NO local policy evaluation — the sidecar
 *   is the single authoritative enforcement boundary.
 *
 *   The sidecar enforces policies locally by default (`decisionMode: "local"`).
 *   Remote decision delegation (`decisionMode: "remote"`) is experimental
 *   and not recommended for production.
 *
 *   `requestCapability()` returns a synthetic grant for backward compat.
 *   Use `requestCapabilityAsync()` for explicit sidecar routing.
 *   `execute()` bypasses the local pipeline entirely and routes directly
 *   to the sidecar `/execute` endpoint.
 *
 *   Local hooks still fire for observability but do not gate decisions.
 *
 * - `"embedded"`: Tools execute in-process with full local policy evaluation.
 *   Security is cooperative — the host could bypass the pipeline.
 *   Suitable for development or trusted environments only.
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
	 * - `"sidecar"` (recommended): acts as a thin client — all policy
	 *   evaluation and tool execution are delegated to the sidecar.
	 *   No local policy evaluation occurs. Requires `sidecar` options.
	 * - `"embedded"`: runs tools in-process with full local policy
	 *   evaluation. Suitable for development or trusted environments only.
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
	/**
	 * Optional external token store. When provided, the firewall uses this
	 * store instead of the default in-memory TokenStore. Use SqliteTokenStore
	 * for persistence across sidecar restarts.
	 */
	tokenStore?: import("./token-store.js").ITokenStore;
}

export function validateOptions(options: FirewallOptions): FirewallOptions {
	firewallConfigSchema.parse({
		principal: options.principal,
		policies: options.policies,
		auditLog: options.auditLog ?? "./audit.db",
	});
	return options;
}
