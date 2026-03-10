import type { Decision } from "./policy.js";
import type { TaintLabel } from "./taint.js";
import type { ToolCall, ToolResult } from "./tool-call.js";

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

/**
 * Kernel-maintained taint state for a run.
 *
 * Tracks accumulated taint independently of tool metadata so that
 * tools/agents cannot silently drop taint labels. Once the run is
 * tainted, the state persists until an explicit policy rule allows
 * taint clearing.
 */
export interface TaintState {
	/** Whether the run has been tainted by any untrusted source. Sticky — never resets. */
	tainted: boolean;
	/** Unique taint source types observed during this run. */
	sources: string[];
	/** Accumulated taint labels from all tool outputs during this run. */
	labels: TaintLabel[];
}

export interface RunContext {
	runId: string;
	principalId: string;
	startedAt: string;
	endedAt?: string;
	eventCount: number;
	startPreviousHash?: string;
	/** Kernel-maintained taint state. Present when the runtime tracks taint. */
	taintState?: TaintState;
}
