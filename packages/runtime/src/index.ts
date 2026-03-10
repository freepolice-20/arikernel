export { Firewall, createFirewall } from "./firewall.js";
export type { FirewallOptions } from "./config.js";
export type { FirewallHooks } from "./hooks.js";
export { CapabilityIssuer, setUntrustedSources, getUntrustedSources } from "./issuer.js";
export { RunStateTracker, isSuspiciousGetExfil } from "./run-state.js";
export type {
	RunStatePolicy,
	RunStateCounters,
	QuarantineInfo,
	QuarantineTrigger,
	SecurityEvent,
	SecurityEventType,
} from "./run-state.js";
export { evaluateBehavioralRules, applyBehavioralRule } from "./behavioral-rules.js";
export { createSecretPatternFilter } from "./output-filter.js";
export type { OutputFilterOptions } from "./output-filter.js";
export type { BehavioralRuleMatch } from "./behavioral-rules.js";
export { TokenStore, type StoredToken } from "./token-store.js";
export { createKernel, getDefaultKernel, resetDefaultKernel } from "./kernel.js";
export type { Kernel, KernelOptions, KernelAllow } from "./kernel.js";
export { canonicalizePath, isPathAllowed } from "./path-security.js";
export { validateCommand } from "./command-security.js";
export { classifyScope } from "./autoscope.js";
export type { ScopeResult } from "./autoscope.js";
export { TraceRecorder, writeTrace, readTrace } from "./trace-recorder.js";
export { replayTrace } from "./replay-engine.js";
export type { ReplayEngineOptions } from "./replay-engine.js";
export {
	TRACE_VERSION,
	type ReplayTrace,
	type TraceEvent,
	type TraceDecision,
	type TraceQuarantine,
	type TraceOutcome,
	type TraceMetadata,
	type ReplayResult as TraceReplayResult,
	type ReplayedEvent,
	type ReplayMismatch,
	type ReplaySummary,
} from "./trace-types.js";
