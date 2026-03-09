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
	/**
	 * Output filter hook (DLP). Called after tool execution and taint propagation.
	 * Return a (potentially redacted) result, or throw to block the response entirely.
	 */
	onOutputFilter?: (toolCall: ToolCall, result: ToolResult) => ToolResult | Promise<ToolResult>;
}
