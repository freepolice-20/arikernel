export { SidecarServer, createSidecarServer, DEFAULT_PORT, DEFAULT_HOST } from "./server.js";
export { SidecarClient } from "./client.js";
export { PrincipalRegistry, resolveRegistryConfig } from "./registry.js";
export {
	enableSidecarGuard,
	disableSidecarGuard,
	isSidecarGuardActive,
	SidecarGuardError,
} from "./guard/sidecar-guard.js";
export type { SidecarGuardOptions } from "./guard/sidecar-guard.js";
export type {
	SidecarConfig,
	ExecuteRequest,
	ExecuteResponse,
	StatusResponse,
} from "./types.js";
