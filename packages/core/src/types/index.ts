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

export {
	type HttpAction,
	type FileAction,
	type ShellAction,
	type DatabaseAction,
	type BrowserAction,
	type RetrievalAction,
	type ActionCategory,
	HTTP_ACTIONS,
	FILE_ACTIONS,
	SHELL_ACTIONS,
	DATABASE_ACTIONS,
	BROWSER_ACTIONS,
	RETRIEVAL_ACTIONS,
	ACTION_CATEGORIES,
	TOOL_CLASS_ACTIONS,
	categorizeAction,
	isKnownAction,
	isWriteAction,
} from "./actions.js";

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
	TaintState,
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
