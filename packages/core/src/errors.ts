import type { Decision } from './types/policy.js';
import type { ToolCall } from './types/tool-call.js';

export class FirewallError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'FirewallError';
	}
}

export class ToolCallDeniedError extends FirewallError {
	constructor(
		public readonly toolCall: ToolCall,
		public readonly decision: Decision,
	) {
		super(`Tool call denied: ${decision.reason}`);
		this.name = 'ToolCallDeniedError';
	}
}

export class ApprovalRequiredError extends FirewallError {
	constructor(
		public readonly toolCall: ToolCall,
		public readonly decision: Decision,
	) {
		super(`Approval required: ${decision.reason}`);
		this.name = 'ApprovalRequiredError';
	}
}

export class PolicyValidationError extends FirewallError {
	constructor(
		message: string,
		public readonly errors: unknown[],
	) {
		super(message);
		this.name = 'PolicyValidationError';
	}
}

export class AuditIntegrityError extends FirewallError {
	constructor(
		message: string,
		public readonly eventId: string,
	) {
		super(message);
		this.name = 'AuditIntegrityError';
	}
}
