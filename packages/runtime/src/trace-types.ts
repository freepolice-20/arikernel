/**
 * Deterministic Attack Replay — Trace Format
 *
 * A normalized, versioned JSON trace that captures enough information
 * to replay a security-relevant run through the kernel deterministically.
 */

import type { Decision, TaintLabel, ToolCallRequest } from "@arikernel/core";
import type { QuarantineInfo, RunStateCounters, SecurityEvent } from "./run-state.js";

/** Current trace format version. Bump on breaking schema changes. */
export const TRACE_VERSION = "1.0";

/** A single recorded tool call attempt and its outcome. */
export interface TraceEvent {
	/** Sequence index within the run (0-based). */
	sequence: number;
	/** ISO 8601 timestamp when the event was recorded. */
	timestamp: string;
	/** The original tool call request (toolClass, action, parameters, taintLabels). */
	request: ToolCallRequest;
	/** Capability class requested before execution, if any. */
	capabilityClass?: string;
	/** Whether the capability was granted. */
	capabilityGranted?: boolean;
	/** The kernel's enforcement decision. */
	decision: TraceDecision;
	/** Run-state counters snapshot after this event. */
	counters: RunStateCounters;
}

/** Normalized decision record for the trace. */
export interface TraceDecision {
	verdict: "allow" | "deny" | "quarantine";
	reason: string;
	matchedRule?: string;
	taintLabels: Array<{ source: string; origin: string }>;
}

/** Quarantine transition recorded in the trace. */
export interface TraceQuarantine {
	/** Sequence index of the event that triggered quarantine. */
	triggeredAtSequence: number;
	/** ISO 8601 timestamp. */
	timestamp: string;
	/** Trigger type: behavioral_rule or threshold. */
	triggerType: "behavioral_rule" | "threshold";
	/** Rule ID if triggered by a behavioral rule. */
	ruleId?: string;
	/** Human-readable reason. */
	reason: string;
	/** The security event pattern that matched. */
	matchedEvents: Array<{ type: string; toolClass?: string; action?: string }>;
	/** Counters at the time of quarantine. */
	counters: RunStateCounters;
}

/** Summary of the run outcome. */
export interface TraceOutcome {
	/** Total tool call attempts. */
	totalEvents: number;
	/** Number of allowed calls. */
	allowed: number;
	/** Number of denied calls. */
	denied: number;
	/** Whether the run entered quarantine. */
	quarantined: boolean;
	/** Final run-state counters. */
	finalCounters: RunStateCounters;
}

/**
 * The top-level deterministic replay trace.
 * A single JSON file capturing a full security-relevant run.
 */
export interface ReplayTrace {
	/** Trace format version (for forward compatibility). */
	traceVersion: string;
	/** Unique run identifier. */
	runId: string;
	/** ISO 8601 timestamp when the run started. */
	timestampStarted: string;
	/** ISO 8601 timestamp when the run completed. */
	timestampCompleted: string;
	/** Optional metadata about the run. */
	metadata: TraceMetadata;
	/** Ordered list of tool call events. */
	events: TraceEvent[];
	/** Quarantine transitions, if any. */
	quarantines: TraceQuarantine[];
	/** Run outcome summary. */
	outcome: TraceOutcome;
}

/** Optional metadata for the trace. */
export interface TraceMetadata {
	/** Principal name. */
	principal?: string;
	/** Preset used, if any. */
	preset?: string;
	/** Description of the scenario. */
	description?: string;
	/** Additional key-value pairs. */
	[key: string]: unknown;
}

/** Result of replaying a trace through the kernel. */
export interface ReplayResult {
	/** The original trace that was replayed. */
	trace: ReplayTrace;
	/** Replayed events with their new decisions. */
	replayedEvents: ReplayedEvent[];
	/** Whether every replayed decision matched the original. */
	allMatched: boolean;
	/** List of mismatches between original and replayed decisions. */
	mismatches: ReplayMismatch[];
	/** Whether the replay reached the same quarantine state. */
	quarantineMatched: boolean;
	/** Summary of the replay. */
	summary: ReplaySummary;
}

/** A single replayed event and comparison. */
export interface ReplayedEvent {
	sequence: number;
	request: ToolCallRequest;
	originalDecision: TraceDecision;
	replayedDecision: TraceDecision;
	matched: boolean;
}

/** A mismatch between original and replayed decision. */
export interface ReplayMismatch {
	sequence: number;
	field: "verdict" | "reason" | "matchedRule";
	original: string;
	replayed: string;
}

/** Aggregate replay summary. */
export interface ReplaySummary {
	totalEvents: number;
	matched: number;
	mismatched: number;
	originalQuarantined: boolean;
	replayQuarantined: boolean;
	allowed: number;
	denied: number;
}
