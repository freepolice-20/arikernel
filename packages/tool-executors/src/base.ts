import type { ToolCall, ToolResult } from '@agent-firewall/core';

export interface ToolExecutor {
	readonly toolClass: string;
	execute(toolCall: ToolCall): Promise<ToolResult>;
}

export const DEFAULT_TIMEOUT_MS = 30_000;
export const DEFAULT_MAX_RESPONSE_SIZE = 10 * 1024 * 1024; // 10MB

export function makeResult(
	callId: string,
	success: boolean,
	startTime: number,
	data?: unknown,
	error?: string,
): Omit<ToolResult, 'taintLabels'> {
	return {
		callId,
		success,
		data,
		error,
		durationMs: Date.now() - startTime,
	};
}
