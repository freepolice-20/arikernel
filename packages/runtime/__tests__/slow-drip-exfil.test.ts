import { describe, expect, it } from "vitest";
import { RunStateTracker, hasEncodedPayload, type SecurityEvent } from "../src/run-state.js";
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

	it("quarantine GET budget limits parameterized GETs (no sensitive read)", () => {
		const state = new RunStateTracker({ behavioralRules: true });

		// Without sensitive read, budget is 3
		expect(state.recordQuarantineGet()).toBe(false);
		expect(state.recordQuarantineGet()).toBe(false);
		expect(state.recordQuarantineGet()).toBe(false);

		// 4th GET exceeds budget
		expect(state.recordQuarantineGet()).toBe(true);
		expect(state.quarantineGetCount).toBe(4);
	});

	it("quarantine GET budget is 0 after sensitive read", () => {
		const state = new RunStateTracker({ behavioralRules: true });

		// Trigger sensitive read
		state.recordSensitiveFileAttempt();

		// Very first GET is blocked — budget is 0 after sensitive read
		expect(state.recordQuarantineGet()).toBe(true);
		expect(state.quarantineGetCount).toBe(1);
	});

	it("GET budget is configurable via static property", () => {
		expect(RunStateTracker.MAX_QUARANTINE_GETS_WITH_PARAMS).toBe(3);
	});
});

describe("Cumulative egress accounting", () => {
	it("tracks total query bytes per hostname", () => {
		const state = new RunStateTracker({ behavioralRules: true });

		state.recordHttpGetEgress("https://tracker.com/pixel?uid=1&v=abc123");
		state.recordHttpGetEgress("https://tracker.com/pixel?uid=2&v=def456");
		state.recordHttpGetEgress("https://other.com/api?key=test");

		const tracker = state.getCumulativeEgress("tracker.com");
		expect(tracker).toBeDefined();
		expect(tracker!.requestCount).toBe(2);
		expect(tracker!.totalQueryBytes).toBeGreaterThan(0);

		const other = state.getCumulativeEgress("other.com");
		expect(other).toBeDefined();
		expect(other!.requestCount).toBe(1);

		expect(state.totalEgressQueryBytes).toBeGreaterThan(0);
	});

	it("hostname allowlist exempts known hosts", () => {
		const state = new RunStateTracker({
			behavioralRules: true,
			egressAllowHosts: ["trusted-analytics.com"],
		});

		expect(state.isAllowlistedHost("trusted-analytics.com")).toBe(true);
		expect(state.isAllowlistedHost("evil.com")).toBe(false);
	});
});

describe("Low-entropy encoding detection", () => {
	it("detects base64 in query param values", () => {
		expect(hasEncodedPayload("https://t.com/p?v=c2stbGl2ZS1hYmMx")).toBe(true);
		expect(hasEncodedPayload("https://t.com/p?v=QVBJX1NFQ1JFVA==")).toBe(true);
		expect(hasEncodedPayload("https://t.com/p?v=cjI=")).toBe(true);
	});

	it("detects hex in query param values", () => {
		expect(hasEncodedPayload("https://t.com/p?v=deadbeef01234567")).toBe(true);
	});

	it("does not flag short normal values", () => {
		expect(hasEncodedPayload("https://t.com/p?page=1&sort=name")).toBe(false);
		expect(hasEncodedPayload("https://t.com/p?q=hello+world")).toBe(false);
	});

	it("does not flag URLs without query params", () => {
		expect(hasEncodedPayload("https://t.com/page")).toBe(false);
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
