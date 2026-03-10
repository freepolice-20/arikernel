export { SidecarServer, createSidecarServer, DEFAULT_PORT, DEFAULT_HOST } from "./server.js";
export type { AuthContext } from "./server.js";
export { SidecarClient } from "./client.js";
export { PrincipalRegistry, resolveRegistryConfig } from "./registry.js";
export { RateLimiter } from "./rate-limiter.js";
export {
	enableSidecarGuard,
	disableSidecarGuard,
	isSidecarGuardActive,
	SidecarGuardError,
} from "./guard/sidecar-guard.js";
export type { SidecarGuardOptions } from "./guard/sidecar-guard.js";
export { SharedTaintRegistry } from "./shared-taint-registry.js";
export type { SharedStoreConfig } from "./shared-taint-registry.js";
export { CrossPrincipalCorrelator } from "./correlator.js";
export type {
	CorrelatorConfig,
	CrossPrincipalAlert,
	AlertHandler,
} from "./correlator.js";
export type {
	SidecarConfig,
	ExecuteRequest,
	ExecuteResponse,
	StatusResponse,
	RequestCapabilityRequest,
	RequestCapabilityResponse,
	PrincipalCredentials,
	RateLimitConfig,
} from "./types.js";
