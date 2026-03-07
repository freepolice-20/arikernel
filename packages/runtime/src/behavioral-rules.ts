/**
 * Behavioral sequence rules for run-state enforcement.
 *
 * Three explicit rules that detect suspicious multi-step patterns
 * in the recent-event window and trigger immediate quarantine.
 * No DSL, no graph engine — just direct pattern matching.
 */

import type { QuarantineInfo, RunStateTracker, SecurityEvent } from './run-state.js';

export interface BehavioralRuleMatch {
	ruleId: string;
	reason: string;
	matchedEvents: SecurityEvent[];
}

/**
 * Risk ordering for tool classes. Higher number = more dangerous.
 * Used by rule 2 to detect capability escalation.
 */
const TOOL_CLASS_RISK: Record<string, number> = {
	http: 1,     // read-only HTTP is low risk
	database: 2, // data access
	file: 3,     // filesystem access
	shell: 5,    // arbitrary code execution
};

const DANGEROUS_CLASSES = new Set(['shell', 'file']);

/**
 * Evaluate all behavioral sequence rules against the recent-event window.
 * Returns the first matching rule, or null if none match.
 */
export function evaluateBehavioralRules(state: RunStateTracker): BehavioralRuleMatch | null {
	if (state.restricted) return null;

	const events = state.recentEvents;
	if (events.length < 2) return null;

	return (
		checkWebTaintSensitiveProbe(events) ??
		checkDeniedCapabilityThenEscalation(events) ??
		checkSensitiveReadThenEgress(events)
	);
}

/**
 * Apply a behavioral rule match to quarantine the run.
 * Returns QuarantineInfo if newly quarantined, null if already restricted.
 */
export function applyBehavioralRule(
	state: RunStateTracker,
	match: BehavioralRuleMatch,
): QuarantineInfo | null {
	return state.quarantineByRule(match.ruleId, match.reason, match.matchedEvents);
}

// ── Rule 1: web_taint_sensitive_probe ──────────────────────────────
//
// If untrusted web taint was recently observed, and shortly after the run
// attempts sensitive file reads, shell exec, or outbound egress → quarantine.

function checkWebTaintSensitiveProbe(events: readonly SecurityEvent[]): BehavioralRuleMatch | null {
	const taintEvent = findRecent(events, (e) =>
		e.type === 'taint_observed' &&
		e.taintSources?.some((s) => s === 'web' || s === 'rag' || s === 'email') === true,
	);
	if (!taintEvent) return null;

	const taintIdx = events.indexOf(taintEvent);

	// Look for dangerous follow-up actions AFTER the taint observation
	const dangerousFollowup = findAfter(events, taintIdx, (e) =>
		e.type === 'sensitive_read_attempt' ||
		(e.type === 'tool_call_denied' && e.toolClass === 'shell') ||
		(e.type === 'tool_call_allowed' && e.toolClass === 'shell') ||
		e.type === 'egress_attempt',
	);

	if (!dangerousFollowup) return null;

	const actionDesc = dangerousFollowup.toolClass
		? `${dangerousFollowup.toolClass}.${dangerousFollowup.action ?? '*'}`
		: dangerousFollowup.type;

	return {
		ruleId: 'web_taint_sensitive_probe',
		reason: `Untrusted web input was followed by ${actionDesc} attempt`,
		matchedEvents: [taintEvent, dangerousFollowup],
	};
}

// ── Rule 2: denied_capability_then_escalation ──────────────────────
//
// If a capability request is denied, and shortly after the run requests
// a broader or riskier capability → quarantine.

function checkDeniedCapabilityThenEscalation(events: readonly SecurityEvent[]): BehavioralRuleMatch | null {
	const deniedCap = findRecent(events, (e) => e.type === 'capability_denied');
	if (!deniedCap) return null;

	const deniedIdx = events.indexOf(deniedCap);
	const deniedRisk = TOOL_CLASS_RISK[deniedCap.toolClass ?? ''] ?? 0;

	// Look for a subsequent capability request that is riskier
	const escalation = findAfter(events, deniedIdx, (e) => {
		if (e.type !== 'capability_requested' && e.type !== 'capability_granted') return false;
		const requestedRisk = TOOL_CLASS_RISK[e.toolClass ?? ''] ?? 0;

		// Escalation: requesting something riskier, or requesting a dangerous class
		if (requestedRisk > deniedRisk) return true;
		if (DANGEROUS_CLASSES.has(e.toolClass ?? '')) return true;

		return false;
	});

	if (!escalation) return null;

	return {
		ruleId: 'denied_capability_then_escalation',
		reason: `Denied ${deniedCap.toolClass ?? 'unknown'} capability was followed by escalation to ${escalation.toolClass ?? 'unknown'}`,
		matchedEvents: [deniedCap, escalation],
	};
}

// ── Rule 3: sensitive_read_then_egress ─────────────────────────────
//
// If the run reads (or attempts to read) sensitive local data, and
// shortly after attempts outbound POST/write/upload → quarantine.

function checkSensitiveReadThenEgress(events: readonly SecurityEvent[]): BehavioralRuleMatch | null {
	const sensitiveRead = findRecent(events, (e) =>
		e.type === 'sensitive_read_attempt' || e.type === 'sensitive_read_allowed',
	);
	if (!sensitiveRead) return null;

	const readIdx = events.indexOf(sensitiveRead);

	const egress = findAfter(events, readIdx, (e) => e.type === 'egress_attempt');

	if (!egress) return null;

	const path = (sensitiveRead.metadata?.path as string) ?? 'sensitive file';

	return {
		ruleId: 'sensitive_read_then_egress',
		reason: `Read of ${path} was followed by outbound ${egress.action ?? 'write'} attempt`,
		matchedEvents: [sensitiveRead, egress],
	};
}

// ── Helpers ────────────────────────────────────────────────────────

function findRecent(
	events: readonly SecurityEvent[],
	predicate: (e: SecurityEvent) => boolean,
): SecurityEvent | null {
	// Search backwards to find the most recent match
	for (let i = events.length - 1; i >= 0; i--) {
		if (predicate(events[i])) return events[i];
	}
	return null;
}

function findAfter(
	events: readonly SecurityEvent[],
	afterIndex: number,
	predicate: (e: SecurityEvent) => boolean,
): SecurityEvent | null {
	for (let i = afterIndex + 1; i < events.length; i++) {
		if (predicate(events[i])) return events[i];
	}
	return null;
}
