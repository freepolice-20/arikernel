import type { AuditEvent, Decision, ToolCall, ToolResult } from '@agent-firewall/core';

export interface FirewallHooks {
	onDecision?: (toolCall: ToolCall, decision: Decision) => void;
	onExecute?: (toolCall: ToolCall, result: ToolResult) => void;
	onAudit?: (event: AuditEvent) => void;
	onApprovalRequired?: (toolCall: ToolCall, decision: Decision) => Promise<boolean>;
}
