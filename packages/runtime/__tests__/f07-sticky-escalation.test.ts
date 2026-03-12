/**
 * F-07 regression tests: Rule 2 (denied_capability_then_escalation)
 * must use a sticky flag so that window eviction does not reset
 * escalation detection state.
 */

import { describe, expect, it } from "vitest";
import { evaluateBehavioralRules } from "../src/behavioral-rules.js";
import { RunStateTracker, type SecurityEvent } from "../src/run-state.js";

function makeEvent(overrides: Partial<SecurityEvent>): SecurityEvent {
	return {
		timestamp: new Date().toISOString(),
		type: "tool_call_allowed",
		...overrides,
	};
}

function pushFillerEvents(state: RunStateTracker, count: number): void {
	for (let i = 0; i < count; i++) {
		state.pushEvent(makeEvent({ type: "tool_call_allowed", toolClass: "http", action: "get" }));
	}
}

describe("F-07: Rule 2 sticky flag for denied_capability_then_escalation", () => {
	it("triggers when denial and escalation are both in window", () => {
		const state = new RunStateTracker({ behavioralRules: true });

		state.pushEvent(makeEvent({ type: "capability_denied", toolClass: "http" }));
		state.pushEvent(makeEvent({ type: "capability_requested", toolClass: "shell" }));

		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match?.ruleId).toBe("denied_capability_then_escalation");
	});

	it("triggers via sticky flag after denial is evicted from window", () => {
		const state = new RunStateTracker({ behavioralRules: true });

		// Need at least 2 events for evaluateBehavioralRules to proceed
		state.pushEvent(makeEvent({ type: "tool_call_allowed", toolClass: "http", action: "get" }));

		// Deny an HTTP capability
		state.pushEvent(makeEvent({ type: "capability_denied", toolClass: "http" }));

		// Evaluate once so the sticky flag gets set by Rule 2 scanning the window
		evaluateBehavioralRules(state);
		expect(state.escalationDeniedObserved).toBe(true);

		// Push 25 filler events to evict the denial from the 20-event window
		pushFillerEvents(state, 25);

		// Now request a riskier capability (shell > http)
		state.pushEvent(makeEvent({ type: "capability_requested", toolClass: "shell" }));

		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match?.ruleId).toBe("denied_capability_then_escalation");
		expect(match?.reason).toContain("Previous denied");
	});

	it("multiple benign events between denial and escalation still trigger", () => {
		const state = new RunStateTracker({ behavioralRules: true });

		// Need at least 2 events for evaluateBehavioralRules to proceed
		state.pushEvent(makeEvent({ type: "tool_call_allowed", toolClass: "http", action: "get" }));

		// Deny a database capability
		state.pushEvent(makeEvent({ type: "capability_denied", toolClass: "database" }));

		// Evaluate to set sticky flag
		evaluateBehavioralRules(state);
		expect(state.escalationDeniedObserved).toBe(true);

		// 30 benign HTTP GET events (well beyond the 20-event window)
		pushFillerEvents(state, 30);

		// Now request file access (risk 3 > database risk 2)
		state.pushEvent(makeEvent({ type: "capability_requested", toolClass: "file" }));

		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match?.ruleId).toBe("denied_capability_then_escalation");
	});

	it("does NOT trigger when escalation is to a lower-risk class", () => {
		const state = new RunStateTracker({ behavioralRules: true });

		state.pushEvent(makeEvent({ type: "tool_call_allowed", toolClass: "http", action: "get" }));

		// Deny a shell capability (risk 5)
		state.pushEvent(makeEvent({ type: "capability_denied", toolClass: "shell" }));

		// Evaluate to set sticky flag
		evaluateBehavioralRules(state);

		// Evict from window
		pushFillerEvents(state, 25);

		// Request HTTP (risk 1 < shell risk 5, and not a dangerous class)
		state.pushEvent(makeEvent({ type: "capability_requested", toolClass: "http" }));

		const match = evaluateBehavioralRules(state);
		// Should not trigger Rule 2 (http is lower risk than shell)
		expect(match === null || match.ruleId !== "denied_capability_then_escalation").toBe(true);
	});

	it("sticky flag tracks highest-risk denied class", () => {
		const state = new RunStateTracker({ behavioralRules: true });

		// First deny HTTP (risk 1), then deny database (risk 2)
		state.pushEvent(makeEvent({ type: "capability_denied", toolClass: "http" }));
		state.pushEvent(makeEvent({ type: "capability_denied", toolClass: "database" }));

		// Evaluate to set sticky flags
		evaluateBehavioralRules(state);

		// Evict from window
		pushFillerEvents(state, 25);

		// Request file (risk 3 > database risk 2) — should trigger
		state.pushEvent(makeEvent({ type: "capability_requested", toolClass: "file" }));

		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match?.ruleId).toBe("denied_capability_then_escalation");
	});

	it("does NOT trigger without any prior denial", () => {
		const state = new RunStateTracker({ behavioralRules: true });

		pushFillerEvents(state, 10);
		state.pushEvent(makeEvent({ type: "capability_requested", toolClass: "shell" }));

		const match = evaluateBehavioralRules(state);
		// No denial → no Rule 2 match (other rules may match but not this one)
		expect(match === null || match.ruleId !== "denied_capability_then_escalation").toBe(true);
	});

	it("escalationDeniedObserved sticky flag persists on RunStateTracker", () => {
		const state = new RunStateTracker({ behavioralRules: true });
		expect(state.escalationDeniedObserved).toBe(false);

		state.markEscalationDenied("http");
		expect(state.escalationDeniedObserved).toBe(true);
		// escalationDeniedToolClass returns the highest-risk class from the set
		expect(state.escalationDeniedToolClass).toBe("http");
		expect(state.escalationDeniedClasses.has("http")).toBe(true);

		// Both classes accumulate in the set; highest-risk getter returns file
		state.markEscalationDenied("file");
		expect(state.escalationDeniedToolClass).toBe("file");
		expect(state.escalationDeniedClasses.has("http")).toBe(true);
		expect(state.escalationDeniedClasses.has("file")).toBe(true);

		// Adding a lower-risk class doesn't change highest-risk getter
		state.markEscalationDenied("http");
		expect(state.escalationDeniedToolClass).toBe("file");
	});

	it("NF-06: lower-risk denial (http) is not lost after higher-risk denial (shell)", () => {
		const state = new RunStateTracker({ behavioralRules: true });

		// Need at least 2 events to proceed
		state.pushEvent(makeEvent({ type: "tool_call_allowed", toolClass: "http", action: "get" }));

		// Deny http (risk 1), then deny shell (risk 5)
		state.pushEvent(makeEvent({ type: "capability_denied", toolClass: "http" }));
		state.pushEvent(makeEvent({ type: "capability_denied", toolClass: "shell" }));

		// Evaluate to set sticky flags for both denials
		evaluateBehavioralRules(state);
		expect(state.escalationDeniedClasses.has("http")).toBe(true);
		expect(state.escalationDeniedClasses.has("shell")).toBe(true);

		// Evict both denials from the window
		pushFillerEvents(state, 25);

		// Request database (risk 2): riskier than http (1) but not than shell (5)
		// Old single-slot: only shell tracked → database < shell → no match
		// New Set: http also tracked → database > http → should trigger
		state.pushEvent(makeEvent({ type: "capability_requested", toolClass: "database" }));

		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match?.ruleId).toBe("denied_capability_then_escalation");
	});
});
