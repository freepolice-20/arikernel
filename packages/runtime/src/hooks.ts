import type {
	AuditEvent,
	CapabilityRequest,
	Decision,
	IssuanceDecision,
	ToolCall,
	ToolResult,
} from '@arikernel/core';

export interface FirewallHooks {
	onDecision?: (toolCall: ToolCall, decision: Decision) => void;
	onExecute?: (toolCall: ToolCall, result: ToolResult) => void;
	onAudit?: (event: AuditEvent) => void;
	onApprovalRequired?: (toolCall: ToolCall, decision: Decision) => Promise<boolean>;
	onIssuance?: (request: CapabilityRequest, decision: IssuanceDecision) => void;
}
