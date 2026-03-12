/**
 * Regression tests: assert that documented production defaults match code.
 *
 * These tests verify claims made in production-hardening.md and security-model.md
 * by checking actual default values in the codebase. If a default changes,
 * these tests fail — forcing an update to both code and documentation.
 */
import { describe, expect, it } from "vitest";
import { RunStateTracker } from "../src/run-state.js";

// ---------------------------------------------------------------------------
// RunStateTracker defaults
// ---------------------------------------------------------------------------

describe("documented defaults: RunStateTracker (regression)", () => {
	it("behavioral rules are enabled by default (no policy)", () => {
		const state = new RunStateTracker();
		expect(state.behavioralRulesEnabled).toBe(true);
	});

	it("behavioral rules are enabled by default (empty policy)", () => {
		const state = new RunStateTracker({});
		expect(state.behavioralRulesEnabled).toBe(true);
	});

	it("behavioral rules can be explicitly disabled", () => {
		const state = new RunStateTracker({ behavioralRules: false });
		expect(state.behavioralRulesEnabled).toBe(false);
	});

	it("maxDeniedSensitiveActions defaults to 5", () => {
		const state = new RunStateTracker();
		// Trigger 4 denials — should not enter restricted mode
		for (let i = 0; i < 4; i++) {
			state.recordDeniedAction();
		}
		expect(state.restricted).toBe(false);

		// 5th denial should trigger restricted mode
		state.recordDeniedAction();
		expect(state.restricted).toBe(true);
		expect(state.quarantineInfo?.triggerType).toBe("threshold");
	});

	it("MAX_QUARANTINE_GETS_WITH_PARAMS is 3 (doc: quarantine GET budget)", () => {
		expect(RunStateTracker.MAX_QUARANTINE_GETS_WITH_PARAMS).toBe(3);
	});

	it("counters start at zero", () => {
		const state = new RunStateTracker();
		expect(state.counters.deniedActions).toBe(0);
		expect(state.counters.capabilityRequests).toBe(0);
		expect(state.counters.deniedCapabilityRequests).toBe(0);
		expect(state.counters.externalEgressAttempts).toBe(0);
		expect(state.counters.sensitiveFileReadAttempts).toBe(0);
	});

	it("sticky flags start false", () => {
		const state = new RunStateTracker();
		expect(state.sensitiveReadObserved).toBe(false);
		expect(state.egressObserved).toBe(false);
		expect(state.secretAccessObserved).toBe(false);
		expect(state.escalationDeniedObserved).toBe(false);
		expect(state.tainted).toBe(false);
	});

	it("taint is sticky — never resets once set", () => {
		const state = new RunStateTracker();
		state.markTainted("web");
		expect(state.tainted).toBe(true);
		// There is no unmarkTainted — verify the property is still true
		expect(state.tainted).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// Restricted mode: safe read-only actions
// ---------------------------------------------------------------------------

describe("documented defaults: restricted mode safe actions (regression)", () => {
	it("http.get is safe (allowed in quarantine)", () => {
		const state = new RunStateTracker();
		expect(state.isAllowedInRestrictedMode("http", "get")).toBe(true);
	});

	it("http.head is safe (allowed in quarantine)", () => {
		const state = new RunStateTracker();
		expect(state.isAllowedInRestrictedMode("http", "head")).toBe(true);
	});

	it("http.options is safe (allowed in quarantine)", () => {
		const state = new RunStateTracker();
		expect(state.isAllowedInRestrictedMode("http", "options")).toBe(true);
	});

	it("http.post is NOT safe (blocked in quarantine)", () => {
		const state = new RunStateTracker();
		expect(state.isAllowedInRestrictedMode("http", "post")).toBe(false);
	});

	it("http.put is NOT safe (blocked in quarantine)", () => {
		const state = new RunStateTracker();
		expect(state.isAllowedInRestrictedMode("http", "put")).toBe(false);
	});

	it("http.patch is NOT safe (blocked in quarantine)", () => {
		const state = new RunStateTracker();
		expect(state.isAllowedInRestrictedMode("http", "patch")).toBe(false);
	});

	it("http.delete is NOT safe (blocked in quarantine)", () => {
		const state = new RunStateTracker();
		expect(state.isAllowedInRestrictedMode("http", "delete")).toBe(false);
	});

	it("file.read is safe (allowed in quarantine)", () => {
		const state = new RunStateTracker();
		expect(state.isAllowedInRestrictedMode("file", "read")).toBe(true);
	});

	it("file.write is NOT safe (blocked in quarantine)", () => {
		const state = new RunStateTracker();
		expect(state.isAllowedInRestrictedMode("file", "write")).toBe(false);
	});

	it("database.query is safe (allowed in quarantine)", () => {
		const state = new RunStateTracker();
		expect(state.isAllowedInRestrictedMode("database", "query")).toBe(true);
	});

	it("database.exec is NOT safe (blocked in quarantine)", () => {
		const state = new RunStateTracker();
		expect(state.isAllowedInRestrictedMode("database", "exec")).toBe(false);
	});

	it("shell.exec is NOT safe (blocked in quarantine)", () => {
		const state = new RunStateTracker();
		expect(state.isAllowedInRestrictedMode("shell", "exec")).toBe(false);
	});

	it("unknown tool class is NOT safe (fail-closed)", () => {
		const state = new RunStateTracker();
		expect(state.isAllowedInRestrictedMode("unknown", "anything")).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// Sensitive path patterns
// ---------------------------------------------------------------------------

describe("documented defaults: sensitive path patterns (regression)", () => {
	const state = new RunStateTracker();

	const sensitivePaths = [
		"/home/user/.ssh/id_rsa",
		"/app/.env",
		"/home/user/.aws/credentials",
		"/etc/credentials.json",
		"/app/password.txt",
		"/vault/secret.key",
		"/home/user/.gnupg/secring.gpg",
		"/home/user/.kube/config",
		"/app/token.json",
	];

	for (const p of sensitivePaths) {
		it(`detects ${p} as sensitive`, () => {
			expect(state.isSensitivePath(p)).toBe(true);
		});
	}

	const nonSensitivePaths = [
		"/app/data/report.csv",
		"/app/src/index.ts",
		"/app/README.md",
		"/app/package.json",
	];

	for (const p of nonSensitivePaths) {
		it(`does NOT flag ${p} as sensitive`, () => {
			expect(state.isSensitivePath(p)).toBe(false);
		});
	}
});

// ---------------------------------------------------------------------------
// Egress classification
// ---------------------------------------------------------------------------

describe("documented defaults: egress classification (regression)", () => {
	const state = new RunStateTracker();

	it("POST is egress", () => expect(state.isEgressAction("post")).toBe(true));
	it("PUT is egress", () => expect(state.isEgressAction("put")).toBe(true));
	it("PATCH is egress", () => expect(state.isEgressAction("patch")).toBe(true));
	it("DELETE is egress", () => expect(state.isEgressAction("delete")).toBe(true));
	it("GET is NOT egress", () => expect(state.isEgressAction("get")).toBe(false));
	it("HEAD is NOT egress", () => expect(state.isEgressAction("head")).toBe(false));
	it("OPTIONS is NOT egress", () => expect(state.isEgressAction("options")).toBe(false));
});
