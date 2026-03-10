import type { Decision } from './policy.js';
import type { ToolCall, ToolResult } from './tool-call.js';

export interface AuditEvent {
	id: string;
	runId: string;
	sequence: number;
	timestamp: string;
	principalId: string;
	toolCall: ToolCall;
	decision: Decision;
	result?: ToolResult;
	previousHash: string;
	hash: string;
}

export interface RunContext {
	runId: string;
	principalId: string;
	startedAt: string;
	endedAt?: string;
	eventCount: number;
	startPreviousHash?: string;
}
