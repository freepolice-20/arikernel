import { describe, expect, it } from "vitest";
import { RunStateTracker, type SecurityEvent } from "../src/run-state.js";
import { evaluateBehavioralRules } from "../src/behavioral-rules.js";

/**
 * H1 hardening tests: verify that sticky state flags prevent
 * window-eviction evasion of behavioral rules.
 */

function makeEvent(overrides: Partial<SecurityEvent>): SecurityEvent {
	return {
		timestamp: new Date().toISOString(),
		type: "tool_call_allowed",
		...overrides,
	};
}

/** Push N filler events to evict earlier events from the 20-event window. */
function pushFillerEvents(state: RunStateTracker, count: number): void {
	for (let i = 0; i < count; i++) {
		state.pushEvent(makeEvent({ type: "tool_call_allowed", toolClass: "http", action: "get" }));
	}
}

describe("H1: sticky state flags survive window eviction", () => {
	it("sensitive_read_then_egress triggers even after read is evicted from window", () => {
		const state = new RunStateTracker({ behavioralRules: true });

		// Record a sensitive file read
		state.recordSensitiveFileAttempt();
		state.pushEvent(makeEvent({ type: "sensitive_read_attempt", toolClass: "file", action: "read", metadata: { path: "/home/.ssh/id_rsa" } }));

		// Push 25 filler events to evict the sensitive read from the 20-event window
		pushFillerEvents(state, 25);

		// Now push an egress attempt — should still trigger via sticky flag
		state.pushEvent(makeEvent({ type: "egress_attempt", toolClass: "http", action: "post" }));

		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match!.ruleId).toBe("sensitive_read_then_egress");
	});

	it("web_taint_sensitive_probe triggers even after taint event is evicted", () => {
		const state = new RunStateTracker({ behavioralRules: true });

		// Observe web taint
		state.markTainted("web");
		state.pushEvent(makeEvent({ type: "taint_observed", taintSources: ["web"] }));

		// Evict the taint event
		pushFillerEvents(state, 25);

		// Now push a sensitive read — should trigger via sticky taint flag
		state.pushEvent(makeEvent({ type: "sensitive_read_attempt", toolClass: "file", action: "read" }));

		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match!.ruleId).toBe("web_taint_sensitive_probe");
	});

	it("secret_access_then_any_egress triggers even after secret access is evicted", () => {
		const state = new RunStateTracker({ behavioralRules: true });

		// Need at least 2 events for evaluateBehavioralRules to proceed
		state.pushEvent(makeEvent({ type: "tool_call_allowed", toolClass: "file", action: "read" }));

		// Access secrets (this sets sticky flag via the rule)
		state.pushEvent(makeEvent({
			type: "tool_call_allowed",
			toolClass: "database",
			action: "query",
			metadata: { query: "SELECT * FROM secrets" },
		}));

		// Evaluate once to set the sticky flag (no egress yet, returns null)
		evaluateBehavioralRules(state);

		// Evict the secret access event
		pushFillerEvents(state, 25);

		// Now push an egress attempt
		state.pushEvent(makeEvent({ type: "egress_attempt", toolClass: "http", action: "post" }));

		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match!.ruleId).toBe("secret_access_then_any_egress");
	});

	it("tainted_database_write triggers even after taint event is evicted", () => {
		const state = new RunStateTracker({ behavioralRules: true });

		state.markTainted("web");
		state.pushEvent(makeEvent({ type: "taint_observed", taintSources: ["web"] }));

		pushFillerEvents(state, 25);

		state.pushEvent(makeEvent({ type: "tool_call_allowed", toolClass: "database", action: "exec" }));

		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match!.ruleId).toBe("tainted_database_write");
	});

	it("tainted_shell_with_data triggers even after taint event is evicted", () => {
		const state = new RunStateTracker({ behavioralRules: true });

		state.markTainted("rag");
		state.pushEvent(makeEvent({ type: "taint_observed", taintSources: ["rag"] }));

		pushFillerEvents(state, 25);

		state.pushEvent(makeEvent({ type: "tool_call_allowed", toolClass: "shell", action: "exec", metadata: { commandLength: 200 } }));

		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		// Rule 1 (web_taint_sensitive_probe) has higher priority and also matches
		// shell events after taint, so either rule detecting this is valid
		expect(["tainted_shell_with_data", "web_taint_sensitive_probe"]).toContain(match!.ruleId);
	});

	it("does NOT trigger when sticky flags are not set", () => {
		const state = new RunStateTracker({ behavioralRules: true });

		// Just filler + egress — no prior sensitive read or taint
		pushFillerEvents(state, 10);
		state.pushEvent(makeEvent({ type: "egress_attempt", toolClass: "http", action: "post" }));

		const match = evaluateBehavioralRules(state);
		expect(match).toBeNull();
	});
});
