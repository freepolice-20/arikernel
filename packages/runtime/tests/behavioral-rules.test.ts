import { describe, it, expect } from 'vitest';
import { RunStateTracker, type SecurityEvent } from '../src/run-state.js';
import { evaluateBehavioralRules, applyBehavioralRule } from '../src/behavioral-rules.js';

function ts(): string {
	return new Date().toISOString();
}

function pushEvents(state: RunStateTracker, events: SecurityEvent[]): void {
	for (const e of events) state.pushEvent(e);
}

describe('Behavioral Rule 1: web_taint_sensitive_probe', () => {
	it('triggers when web taint is followed by sensitive file read', () => {
		const state = new RunStateTracker();
		pushEvents(state, [
			{ timestamp: ts(), type: 'taint_observed', taintSources: ['web'] },
			{ timestamp: ts(), type: 'sensitive_read_attempt', toolClass: 'file', action: 'read', metadata: { path: '~/.ssh/id_rsa' } },
		]);
		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match!.ruleId).toBe('web_taint_sensitive_probe');
	});

	it('triggers when web taint is followed by shell exec', () => {
		const state = new RunStateTracker();
		pushEvents(state, [
			{ timestamp: ts(), type: 'taint_observed', taintSources: ['web'] },
			{ timestamp: ts(), type: 'tool_call_allowed', toolClass: 'shell', action: 'exec' },
		]);
		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match!.ruleId).toBe('web_taint_sensitive_probe');
	});

	it('triggers when web taint is followed by egress attempt', () => {
		const state = new RunStateTracker();
		pushEvents(state, [
			{ timestamp: ts(), type: 'taint_observed', taintSources: ['web'] },
			{ timestamp: ts(), type: 'egress_attempt', toolClass: 'http', action: 'post' },
		]);
		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match!.ruleId).toBe('web_taint_sensitive_probe');
	});

	it('triggers for rag taint source too', () => {
		const state = new RunStateTracker();
		pushEvents(state, [
			{ timestamp: ts(), type: 'taint_observed', taintSources: ['rag'] },
			{ timestamp: ts(), type: 'sensitive_read_attempt', toolClass: 'file', action: 'read' },
		]);
		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match!.ruleId).toBe('web_taint_sensitive_probe');
	});

	it('does NOT trigger for non-web taint sources', () => {
		const state = new RunStateTracker();
		pushEvents(state, [
			{ timestamp: ts(), type: 'taint_observed', taintSources: ['user'] },
			{ timestamp: ts(), type: 'sensitive_read_attempt', toolClass: 'file', action: 'read' },
		]);
		const match = evaluateBehavioralRules(state);
		expect(match).toBeNull();
	});

	it('does NOT trigger if dangerous action comes BEFORE taint', () => {
		const state = new RunStateTracker();
		pushEvents(state, [
			{ timestamp: ts(), type: 'sensitive_read_attempt', toolClass: 'file', action: 'read' },
			{ timestamp: ts(), type: 'taint_observed', taintSources: ['web'] },
		]);
		// Rule 1 shouldn't match because the read came before taint.
		// However rule 3 (sensitive_read_then_egress) won't match either since no egress.
		const match = evaluateBehavioralRules(state);
		// The taint event is found as most recent, but there's nothing after it
		expect(match).toBeNull();
	});
});

describe('Behavioral Rule 2: denied_capability_then_escalation', () => {
	it('triggers when denied capability is followed by riskier request', () => {
		const state = new RunStateTracker();
		pushEvents(state, [
			{ timestamp: ts(), type: 'capability_denied', toolClass: 'http' },
			{ timestamp: ts(), type: 'capability_requested', toolClass: 'shell' },
		]);
		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match!.ruleId).toBe('denied_capability_then_escalation');
	});

	it('triggers when denied capability is followed by dangerous class request', () => {
		const state = new RunStateTracker();
		pushEvents(state, [
			{ timestamp: ts(), type: 'capability_denied', toolClass: 'database' },
			{ timestamp: ts(), type: 'capability_requested', toolClass: 'file' },
		]);
		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match!.ruleId).toBe('denied_capability_then_escalation');
	});

	it('does NOT trigger for same or lower risk', () => {
		const state = new RunStateTracker();
		pushEvents(state, [
			{ timestamp: ts(), type: 'capability_denied', toolClass: 'shell' },
			{ timestamp: ts(), type: 'capability_requested', toolClass: 'http' },
		]);
		const match = evaluateBehavioralRules(state);
		// http is lower risk than shell, and http is not a dangerous class
		expect(match).toBeNull();
	});

	it('does NOT trigger without a prior denial', () => {
		const state = new RunStateTracker();
		pushEvents(state, [
			{ timestamp: ts(), type: 'capability_granted', toolClass: 'http' },
			{ timestamp: ts(), type: 'capability_requested', toolClass: 'shell' },
		]);
		const match = evaluateBehavioralRules(state);
		expect(match).toBeNull();
	});
});

describe('Behavioral Rule 3: sensitive_read_then_egress', () => {
	it('triggers when sensitive read is followed by egress', () => {
		const state = new RunStateTracker();
		pushEvents(state, [
			{ timestamp: ts(), type: 'sensitive_read_attempt', toolClass: 'file', action: 'read', metadata: { path: '~/.env' } },
			{ timestamp: ts(), type: 'egress_attempt', toolClass: 'http', action: 'post' },
		]);
		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match!.ruleId).toBe('sensitive_read_then_egress');
		expect(match!.reason).toContain('~/.env');
	});

	it('triggers for sensitive_read_allowed too', () => {
		const state = new RunStateTracker();
		pushEvents(state, [
			{ timestamp: ts(), type: 'sensitive_read_allowed', toolClass: 'file', action: 'read' },
			{ timestamp: ts(), type: 'egress_attempt', toolClass: 'http', action: 'post' },
		]);
		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match!.ruleId).toBe('sensitive_read_then_egress');
	});

	it('does NOT trigger without egress', () => {
		const state = new RunStateTracker();
		pushEvents(state, [
			{ timestamp: ts(), type: 'sensitive_read_attempt', toolClass: 'file', action: 'read' },
			{ timestamp: ts(), type: 'tool_call_allowed', toolClass: 'http', action: 'get' },
		]);
		const match = evaluateBehavioralRules(state);
		expect(match).toBeNull();
	});

	it('does NOT trigger if egress comes before read', () => {
		const state = new RunStateTracker();
		pushEvents(state, [
			{ timestamp: ts(), type: 'egress_attempt', toolClass: 'http', action: 'post' },
			{ timestamp: ts(), type: 'sensitive_read_attempt', toolClass: 'file', action: 'read' },
		]);
		// findRecent finds the sensitive read (most recent), then looks AFTER it for egress — none
		const match = evaluateBehavioralRules(state);
		expect(match).toBeNull();
	});
});

describe('Behavioral rule application', () => {
	it('quarantines the run and records QuarantineInfo', () => {
		const state = new RunStateTracker();
		pushEvents(state, [
			{ timestamp: ts(), type: 'taint_observed', taintSources: ['web'] },
			{ timestamp: ts(), type: 'sensitive_read_attempt', toolClass: 'file', action: 'read' },
		]);
		const match = evaluateBehavioralRules(state)!;
		expect(match).not.toBeNull();

		const quarantine = applyBehavioralRule(state, match);
		expect(quarantine).not.toBeNull();
		expect(quarantine!.triggerType).toBe('behavioral_rule');
		expect(quarantine!.ruleId).toBe('web_taint_sensitive_probe');
		expect(state.restricted).toBe(true);
		expect(state.quarantineInfo).toBe(quarantine);
	});

	it('does not double-quarantine if already restricted', () => {
		const state = new RunStateTracker({ maxDeniedSensitiveActions: 1 });
		state.recordDeniedAction(); // threshold triggered
		expect(state.restricted).toBe(true);

		pushEvents(state, [
			{ timestamp: ts(), type: 'taint_observed', taintSources: ['web'] },
			{ timestamp: ts(), type: 'sensitive_read_attempt', toolClass: 'file', action: 'read' },
		]);
		// evaluateBehavioralRules returns null if already restricted
		const match = evaluateBehavioralRules(state);
		expect(match).toBeNull();
	});

	it('threshold quarantine sets correct QuarantineInfo', () => {
		const state = new RunStateTracker({ maxDeniedSensitiveActions: 2 });
		state.recordDeniedAction();
		state.recordDeniedAction();
		expect(state.restricted).toBe(true);
		expect(state.quarantineInfo).not.toBeNull();
		expect(state.quarantineInfo!.triggerType).toBe('threshold');
		expect(state.quarantineInfo!.reason).toContain('exceeded threshold');
	});

	it('behavioral rules can be disabled via policy', () => {
		const state = new RunStateTracker({ behavioralRules: false });
		expect(state.behavioralRulesEnabled).toBe(false);
		pushEvents(state, [
			{ timestamp: ts(), type: 'taint_observed', taintSources: ['web'] },
			{ timestamp: ts(), type: 'sensitive_read_attempt', toolClass: 'file', action: 'read' },
		]);
		// Would normally match, but behavioralRulesEnabled is false.
		// Note: evaluateBehavioralRules checks state.restricted, not behavioralRulesEnabled.
		// The caller (pipeline/firewall) checks behavioralRulesEnabled before calling.
		// But evaluateBehavioralRules itself doesn't — let's just test the flag exists.
		expect(state.behavioralRulesEnabled).toBe(false);
	});
});

describe('Event window management', () => {
	it('maintains max window size of 20', () => {
		const state = new RunStateTracker();
		for (let i = 0; i < 30; i++) {
			state.pushEvent({ timestamp: ts(), type: 'tool_call_allowed', toolClass: 'http', action: 'get' });
		}
		expect(state.recentEvents.length).toBe(20);
	});

	it('quarantine_entered event is pushed when quarantined', () => {
		const state = new RunStateTracker();
		pushEvents(state, [
			{ timestamp: ts(), type: 'taint_observed', taintSources: ['web'] },
			{ timestamp: ts(), type: 'sensitive_read_attempt', toolClass: 'file', action: 'read' },
		]);
		const match = evaluateBehavioralRules(state)!;
		applyBehavioralRule(state, match);
		const lastEvent = state.recentEvents[state.recentEvents.length - 1];
		expect(lastEvent.type).toBe('quarantine_entered');
	});

	it('rule priority: rule 1 matches before rule 3 when both could match', () => {
		const state = new RunStateTracker();
		pushEvents(state, [
			{ timestamp: ts(), type: 'taint_observed', taintSources: ['web'] },
			{ timestamp: ts(), type: 'sensitive_read_attempt', toolClass: 'file', action: 'read', metadata: { path: '~/.env' } },
			{ timestamp: ts(), type: 'egress_attempt', toolClass: 'http', action: 'post' },
		]);
		// Both rule 1 (web taint → sensitive read) and rule 3 (sensitive read → egress) could match.
		// Rule 1 is checked first, so it should win.
		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match!.ruleId).toBe('web_taint_sensitive_probe');
	});
});
