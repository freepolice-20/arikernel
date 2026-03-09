/**
 * Trace Recorder — captures a normalized replay trace from a live run.
 *
 * Hooks into FirewallHooks (onDecision, onAudit, onIssuance) to record
 * events without duplicating business logic.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type {
	AuditEvent,
	CapabilityRequest,
	Decision,
	IssuanceDecision,
	ToolCall,
	ToolCallRequest,
	ToolResult,
} from '@arikernel/core';
import { now } from '@arikernel/core';
import type { FirewallHooks } from './hooks.js';
import type { QuarantineInfo, RunStateCounters } from './run-state.js';
import {
	TRACE_VERSION,
	type ReplayTrace,
	type TraceDecision,
	type TraceEvent,
	type TraceMetadata,
	type TraceQuarantine,
} from './trace-types.js';

interface PendingEvent {
	request: ToolCallRequest;
	capabilityClass?: string;
	capabilityGranted?: boolean;
}

/**
 * Records a deterministic trace from a live Ari Kernel run.
 *
 * Usage:
 * ```ts
 * const recorder = new TraceRecorder({ description: 'prompt injection test' });
 * const firewall = createFirewall({ ...options, hooks: recorder.hooks });
 * // ... run the scenario ...
 * const trace = recorder.finalize(firewall.runId, firewall.quarantineInfo, firewall.runStateCounters);
 * ```
 */
export class TraceRecorder {
	private events: TraceEvent[] = [];
	private quarantines: TraceQuarantine[] = [];
	private pendingCapabilities = new Map<string, { capabilityClass: string; granted: boolean }>();
	private recordedToolCallIds = new Set<string>();
	private startedAt: string;
	private metadata: TraceMetadata;
	private latestCounters: RunStateCounters = {
		deniedActions: 0,
		capabilityRequests: 0,
		deniedCapabilityRequests: 0,
		externalEgressAttempts: 0,
		sensitiveFileReadAttempts: 0,
	};

	/** FirewallHooks to pass to createFirewall(). */
	readonly hooks: FirewallHooks;

	constructor(metadata: TraceMetadata = {}) {
		this.metadata = metadata;
		this.startedAt = now();

		this.hooks = {
			onDecision: (toolCall: ToolCall, decision: Decision) => {
				this.recordEvent(toolCall, decision);
				this.recordedToolCallIds.add(toolCall.id);
			},
			onIssuance: (request: CapabilityRequest, decision: IssuanceDecision) => {
				// Store capability decision to attach to the next tool call event
				this.pendingCapabilities.set(request.principalId, {
					capabilityClass: request.capabilityClass,
					granted: decision.granted,
				});
			},
			onAudit: (event: AuditEvent) => {
				// Detect quarantine system events
				if ((event.toolCall.toolClass as string) === '_system' && event.toolCall.action === 'quarantine') {
					this.recordQuarantine(event);
					return;
				}
				// Capture tool call events that bypassed onDecision
				// (grant constraint violations, quarantine-blocked, missing token)
				if (!this.recordedToolCallIds.has(event.toolCall.id)) {
					this.recordEventFromAudit(event);
					this.recordedToolCallIds.add(event.toolCall.id);
				}
			},
		};
	}

	private recordEvent(toolCall: ToolCall, decision: Decision): void {
		const capInfo = this.pendingCapabilities.get(toolCall.principalId);
		this.pendingCapabilities.delete(toolCall.principalId);

		const traceDecision: TraceDecision = {
			verdict: decision.verdict === 'require-approval' ? 'deny' : decision.verdict,
			reason: decision.reason,
			matchedRule: decision.matchedRule?.id,
			taintLabels: decision.taintLabels.map((t) => ({ source: t.source, origin: t.origin })),
		};

		const event: TraceEvent = {
			sequence: this.events.length,
			timestamp: toolCall.timestamp,
			request: {
				toolClass: toolCall.toolClass,
				action: toolCall.action,
				parameters: toolCall.parameters,
				taintLabels: toolCall.taintLabels,
			},
			capabilityClass: capInfo?.capabilityClass,
			capabilityGranted: capInfo?.granted,
			decision: traceDecision,
			counters: { ...this.latestCounters },
		};

		this.events.push(event);
	}

	private recordEventFromAudit(event: AuditEvent): void {
		const capInfo = this.pendingCapabilities.get(event.toolCall.principalId);
		this.pendingCapabilities.delete(event.toolCall.principalId);

		const traceDecision: TraceDecision = {
			verdict: event.decision.verdict === 'require-approval' ? 'deny' : event.decision.verdict,
			reason: event.decision.reason,
			matchedRule: event.decision.matchedRule?.id,
			taintLabels: event.decision.taintLabels.map((t) => ({ source: t.source, origin: t.origin })),
		};

		const traceEvent: TraceEvent = {
			sequence: this.events.length,
			timestamp: event.toolCall.timestamp,
			request: {
				toolClass: event.toolCall.toolClass,
				action: event.toolCall.action,
				parameters: event.toolCall.parameters,
				taintLabels: event.toolCall.taintLabels,
			},
			capabilityClass: capInfo?.capabilityClass,
			capabilityGranted: capInfo?.granted,
			decision: traceDecision,
			counters: { ...this.latestCounters },
		};

		this.events.push(traceEvent);
	}

	private recordQuarantine(event: AuditEvent): void {
		const params = event.toolCall.parameters;
		const quarantine: TraceQuarantine = {
			triggeredAtSequence: this.events.length - 1,
			timestamp: event.timestamp,
			triggerType: (params.triggerType as 'behavioral_rule' | 'threshold') ?? 'behavioral_rule',
			ruleId: params.ruleId as string | undefined,
			reason: event.decision.reason,
			matchedEvents: Array.isArray(params.matchedEvents)
				? (params.matchedEvents as Array<{ type: string; toolClass?: string; action?: string }>)
				: [],
			counters: (params.counters as RunStateCounters) ?? { ...this.latestCounters },
		};
		this.quarantines.push(quarantine);
	}

	/** Update the latest counters snapshot (call after each event if tracking externally). */
	updateCounters(counters: RunStateCounters): void {
		this.latestCounters = { ...counters };
	}

	/**
	 * Record a capability-level denial that never reached firewall.execute().
	 * Use this when requestCapability() returns granted=false (e.g. quarantine blocks).
	 */
	recordCapabilityDenial(
		capabilityClass: string,
		request: ToolCallRequest,
		reason: string,
	): void {
		const traceEvent: TraceEvent = {
			sequence: this.events.length,
			timestamp: now(),
			request,
			capabilityClass,
			capabilityGranted: false,
			decision: {
				verdict: 'deny',
				reason,
				taintLabels: [],
			},
			counters: { ...this.latestCounters },
		};
		this.events.push(traceEvent);
	}

	/**
	 * Finalize the trace after the run completes.
	 * Returns a complete ReplayTrace ready for serialization.
	 */
	finalize(
		runId: string,
		quarantineInfo: QuarantineInfo | null,
		finalCounters: RunStateCounters,
	): ReplayTrace {
		const allowed = this.events.filter((e) => e.decision.verdict === 'allow').length;
		const denied = this.events.filter((e) => e.decision.verdict === 'deny').length;

		return {
			traceVersion: TRACE_VERSION,
			runId,
			timestampStarted: this.startedAt,
			timestampCompleted: now(),
			metadata: this.metadata,
			events: this.events,
			quarantines: this.quarantines,
			outcome: {
				totalEvents: this.events.length,
				allowed,
				denied,
				quarantined: quarantineInfo !== null || this.quarantines.length > 0,
				finalCounters: { ...finalCounters },
			},
		};
	}
}

/** Write a trace to a JSON file. */
export function writeTrace(trace: ReplayTrace, filePath: string): void {
	const dir = dirname(filePath);
	if (!existsSync(dir)) {
		mkdirSync(dir, { recursive: true });
	}
	writeFileSync(filePath, JSON.stringify(trace, null, 2), 'utf-8');
}

/** Read a trace from a JSON file. */
export function readTrace(filePath: string): ReplayTrace {
	const content = readFileSync(filePath, 'utf-8');
	const trace = JSON.parse(content) as ReplayTrace;
	if (!trace.traceVersion) {
		throw new Error('Invalid trace file: missing traceVersion');
	}
	return trace;
}
