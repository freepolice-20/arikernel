export {
	type ToolClass,
	type Capability,
	type CapabilityConstraints,
	type Principal,
	TOOL_CLASSES,
} from "./principal.js";

export {
	type TaintSource,
	type TaintLabel,
	TAINT_SOURCES,
} from "./taint.js";

export type {
	ToolCallRequest,
	ToolCall,
	ToolResult,
} from "./tool-call.js";

export type {
	DecisionVerdict,
	ParameterMatcher,
	PolicyMatch,
	PolicyRule,
	PolicySet,
	Decision,
} from "./policy.js";

export type {
	AuditEvent,
	RunContext,
} from "./audit.js";

export {
	type CapabilityClass,
	type CapabilityClassMapping,
	type CapabilityConstraint,
	type CapabilityLease,
	type CapabilityRequest,
	type CapabilityGrant,
	type IssuanceDecision,
	CAPABILITY_CLASSES,
	CAPABILITY_CLASS_MAP,
	deriveCapabilityClass,
} from "./capability.js";
