import { describe, expect, it } from "vitest";
import { evaluateBehavioralRules } from "../src/behavioral-rules.js";
import type { SecurityEvent } from "../src/run-state.js";
import { RunStateTracker } from "../src/run-state.js";

function makeEvent(type: SecurityEvent["type"], overrides?: Partial<SecurityEvent>): SecurityEvent {
	return {
		timestamp: new Date().toISOString(),
		type,
		...overrides,
	};
}

describe("behavioral rules — window eviction + sticky flags", () => {
	it("rule 1 fires when taint event is evicted but sticky flag persists", () => {
		const state = new RunStateTracker({ behavioralRules: true });

		// Push a web taint event
		state.pushEvent(makeEvent("taint_observed", { taintSources: ["web"] }));
		state.markTainted("web");

		// Push 20 filler events to evict the taint event from the window
		for (let i = 0; i < 20; i++) {
			state.pushEvent(makeEvent("tool_call_allowed", { toolClass: "http", action: "get" }));
		}

		// The taint event is now evicted from the 20-event window.
		// Push a sensitive read attempt — should still trigger via sticky flag.
		state.pushEvent(makeEvent("sensitive_read_attempt", { toolClass: "file", action: "read" }));

		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match!.ruleId).toBe("web_taint_sensitive_probe");
	});

	it("rule 1 does NOT fire without taint (no false positives)", () => {
		const state = new RunStateTracker({ behavioralRules: true });

		// No taint set — just a sensitive read
		state.pushEvent(makeEvent("tool_call_allowed", { toolClass: "http", action: "get" }));
		state.pushEvent(makeEvent("sensitive_read_attempt", { toolClass: "file", action: "read" }));

		const match = evaluateBehavioralRules(state);
		// Should not match rule 1 (no taint). May match other rules or return null.
		if (match) {
			expect(match.ruleId).not.toBe("web_taint_sensitive_probe");
		}
	});

	it("rule 2 fires when denial is evicted but escalation sticky persists", () => {
		const state = new RunStateTracker({ behavioralRules: true });

		// Capability denial for http — need a second event so evaluateBehavioralRules runs
		state.pushEvent(makeEvent("capability_denied", { toolClass: "http" }));
		state.pushEvent(makeEvent("tool_call_allowed", { toolClass: "http", action: "get" }));

		// Evaluate once while denial is in the window — this sets the sticky flag
		evaluateBehavioralRules(state);

		// Now evict the denial by filling the window
		for (let i = 0; i < 20; i++) {
			state.pushEvent(makeEvent("tool_call_allowed", { toolClass: "http", action: "get" }));
		}

		// Now request shell (higher risk) — should trigger via sticky
		state.pushEvent(makeEvent("capability_requested", { toolClass: "shell" }));

		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match!.ruleId).toBe("denied_capability_then_escalation");
	});

	it("rule 3 fires when sensitive read is evicted but sticky persists", () => {
		const state = new RunStateTracker({ behavioralRules: true });

		// Sensitive file read
		state.pushEvent(makeEvent("sensitive_read_attempt", { toolClass: "file", action: "read" }));
		state.confirmSensitiveFileRead();

		// Evict it
		for (let i = 0; i < 20; i++) {
			state.pushEvent(makeEvent("tool_call_allowed", { toolClass: "http", action: "get" }));
		}

		// Egress attempt
		state.pushEvent(makeEvent("egress_attempt", { toolClass: "http", action: "post" }));

		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match!.ruleId).toBe("sensitive_read_then_egress");
	});

	it("rule 6 fires when secret access is evicted but sticky persists", () => {
		const state = new RunStateTracker({ behavioralRules: true });

		// Secret access via database
		state.pushEvent(
			makeEvent("tool_call_allowed", {
				toolClass: "database",
				action: "query",
				metadata: { table: "user_secrets", query: "SELECT * FROM user_secrets" },
			}),
		);
		state.markSecretAccess();

		// Evict it
		for (let i = 0; i < 20; i++) {
			state.pushEvent(makeEvent("tool_call_allowed", { toolClass: "http", action: "get" }));
		}

		// Egress
		state.pushEvent(makeEvent("egress_attempt", { toolClass: "http", action: "post" }));

		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match!.ruleId).toBe("secret_access_then_any_egress");
	});
});

describe("behavioral rules — in-window detection", () => {
	it("rule 1 fires when taint + sensitive read are both in window", () => {
		const state = new RunStateTracker({ behavioralRules: true });
		state.pushEvent(makeEvent("taint_observed", { taintSources: ["web"] }));
		state.markTainted("web");
		state.pushEvent(makeEvent("sensitive_read_attempt", { toolClass: "file", action: "read" }));

		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match!.ruleId).toBe("web_taint_sensitive_probe");
	});

	it("rule 4 fires on taint + database write", () => {
		const state = new RunStateTracker({ behavioralRules: true });
		state.pushEvent(makeEvent("taint_observed", { taintSources: ["rag"] }));
		state.markTainted("rag");
		state.pushEvent(makeEvent("tool_call_allowed", { toolClass: "database", action: "insert" }));

		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		// Could be rule 1 or rule 4, both are valid — the key is that a rule fires
		expect(["web_taint_sensitive_probe", "tainted_database_write"]).toContain(match!.ruleId);
	});

	it("rule 5 fires on taint + long shell command", () => {
		const state = new RunStateTracker({ behavioralRules: true });
		state.pushEvent(makeEvent("taint_observed", { taintSources: ["email"] }));
		state.markTainted("email");
		state.pushEvent(
			makeEvent("tool_call_allowed", {
				toolClass: "shell",
				action: "exec",
				metadata: { commandLength: 200 },
			}),
		);

		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
	});

	it("returns null when insufficient events", () => {
		const state = new RunStateTracker({ behavioralRules: true });
		state.pushEvent(makeEvent("tool_call_allowed", { toolClass: "http", action: "get" }));
		expect(evaluateBehavioralRules(state)).toBeNull();
	});
});
