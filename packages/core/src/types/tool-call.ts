import type { TaintLabel } from './taint.js';
import type { ToolClass } from './principal.js';

export interface ToolCallRequest {
	toolClass: ToolClass;
	action: string;
	parameters: Record<string, unknown>;
	taintLabels?: TaintLabel[];
	parentCallId?: string;
	grantId?: string;
}

export interface ToolCall {
	id: string;
	runId: string;
	sequence: number;
	timestamp: string;
	principalId: string;
	toolClass: ToolClass;
	action: string;
	parameters: Record<string, unknown>;
	taintLabels: TaintLabel[];
	parentCallId?: string;
	grantId?: string;
}

export interface ToolResult {
	callId: string;
	success: boolean;
	data?: unknown;
	error?: string;
	taintLabels: TaintLabel[];
	durationMs: number;
}
