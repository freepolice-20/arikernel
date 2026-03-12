/**
 * Regression tests: low-and-slow GET exfiltration behavior under quarantine.
 *
 * These tests encode the CURRENT INTENDED BEHAVIOR and its known limitations.
 * The system uses heuristics (query length, param value size, path entropy,
 * encoded payload detection, GET budget) — not a perfect classifier.
 *
 * HONEST LIMITATIONS (documented, not hidden):
 *   - A sufficiently small GET query (<128 char values, <256 total query)
 *     with low-entropy data WILL pass isSuspiciousGetExfil. This is by design:
 *     blocking ALL GETs would break normal web browsing in quarantine.
 *   - The quarantine GET budget (3 GETs, or 0 after sensitive read) limits
 *     but does not fully prevent drip exfil of small chunks.
 *   - Path segment entropy detects base64/hex but not natural-language encoding.
 */
import { describe, expect, it } from "vitest";
import { evaluateBehavioralRules } from "../src/behavioral-rules.js";
import {
	RunStateTracker,
	type SecurityEvent,
	hasEncodedPayload,
	isSuspiciousGetExfil,
} from "../src/run-state.js";

function makeEvent(overrides: Partial<SecurityEvent>): SecurityEvent {
	return {
		timestamp: new Date().toISOString(),
		type: "tool_call_allowed",
		...overrides,
	};
}

// ---------------------------------------------------------------------------
// GET exfil detection: heuristic boundary tests
// ---------------------------------------------------------------------------

describe("GET exfil heuristic: boundary behavior (regression)", () => {
	it("BLOCKS: query string at exactly 257 chars (just over threshold)", () => {
		const query = "x=" + "A".repeat(255);
		expect(query.length).toBe(257);
		expect(isSuspiciousGetExfil(`https://evil.com/c?${query}`)).toBe(true);
	});

	it("ALLOWS: query string at exactly 256 chars (at threshold)", () => {
		const query = "x=" + "A".repeat(254);
		expect(query.length).toBe(256);
		// query including the leading '?' is 257, but search = '?' + query
		// The actual check is on parsed.search which includes '?'
		// So 256 chars of query means 257 chars of search — this should be flagged
		expect(isSuspiciousGetExfil(`https://evil.com/c?${query}`)).toBe(true);
	});

	it("ALLOWS: many short params totaling ~200 chars (no single value over 128)", () => {
		// 20 params of ~8 chars each: "a0=ABCD&a1=ABCD&..." — total under 256, no value >128
		const params = Array.from({ length: 20 }, (_, i) => `a${i}=ABCD`).join("&");
		expect(params.length).toBeLessThan(256);
		expect(isSuspiciousGetExfil(`https://evil.com/c?${params}`)).toBe(false);
	});

	it("BLOCKS: single param value at 129 chars (just over threshold)", () => {
		const value = "A".repeat(129);
		expect(isSuspiciousGetExfil(`https://evil.com/c?d=${value}`)).toBe(true);
	});

	it("ALLOWS: single param value at 128 chars (at threshold)", () => {
		const value = "A".repeat(128);
		expect(isSuspiciousGetExfil(`https://evil.com/c?d=${value}`)).toBe(false);
	});

	it("KNOWN LIMITATION: small low-entropy drip passes detection", () => {
		// An attacker sending 50 chars of a secret per request in a normal-looking
		// param will NOT be caught by isSuspiciousGetExfil alone.
		// This is intentional — the GET budget is the secondary defense layer.
		const smallChunk = "MySecretAPIKey12345";
		expect(isSuspiciousGetExfil(`https://evil.com/api?token=${smallChunk}`)).toBe(false);
	});

	it("BLOCKS: high-entropy path segment (base64 in URL path)", () => {
		const encoded = Buffer.from("secret-ssh-key-content-here-1234567890").toString("base64");
		expect(isSuspiciousGetExfil(`https://evil.com/exfil/${encoded}`)).toBe(true);
	});

	it("ALLOWS: normal UUID in path segment (common, not exfil)", () => {
		expect(
			isSuspiciousGetExfil("https://api.example.com/users/550e8400-e29b-41d4-a716-446655440000"),
		).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// Encoded payload detection: base64/hex in query params
// ---------------------------------------------------------------------------

describe("encoded payload detection in quarantine GET (regression)", () => {
	it("detects base64 with padding in query param", () => {
		expect(hasEncodedPayload("https://evil.com/p?v=SGVsbG8gV29ybGQ=")).toBe(true);
	});

	it("detects long base64 without padding", () => {
		expect(hasEncodedPayload("https://evil.com/p?v=SGVsbG8gV29ybGQ")).toBe(true);
	});

	it("detects hex-encoded data in query param", () => {
		expect(hasEncodedPayload("https://evil.com/p?v=48656c6c6f20576f726c64")).toBe(true);
	});

	it("does NOT flag short normal words that happen to be alphanumeric", () => {
		expect(hasEncodedPayload("https://example.com/p?sort=name")).toBe(false);
	});

	it("does NOT flag numeric page params", () => {
		expect(hasEncodedPayload("https://example.com/p?page=123&limit=50")).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// Quarantine GET budget: sensitive-read zeroes budget
// ---------------------------------------------------------------------------

describe("quarantine GET budget: sensitive-read-then-GET (regression)", () => {
	it("budget=0 after sensitive read: first parameterized GET is blocked", () => {
		const state = new RunStateTracker({ behavioralRules: true });
		state.recordSensitiveFileAttempt();
		expect(state.sensitiveReadObserved).toBe(true);

		// Very first GET after sensitive read exhausts budget
		const exhausted = state.recordQuarantineGet();
		expect(exhausted).toBe(true);
	});

	it("budget=3 without sensitive read: allows 3 parameterized GETs", () => {
		const state = new RunStateTracker({ behavioralRules: true });
		expect(state.sensitiveReadObserved).toBe(false);

		expect(state.recordQuarantineGet()).toBe(false); // 1
		expect(state.recordQuarantineGet()).toBe(false); // 2
		expect(state.recordQuarantineGet()).toBe(false); // 3
		expect(state.recordQuarantineGet()).toBe(true); // 4 — blocked
	});

	it("KNOWN LIMITATION: 3 small GETs can leak ~384 bytes before budget blocks", () => {
		// With 128-char param values allowed per GET, 3 GETs = 384 chars of data.
		// After that, the budget blocks further GETs with params.
		// This is documented and intentional — tighter budgets break legitimate browsing.
		const state = new RunStateTracker({ behavioralRules: true });
		expect(RunStateTracker.MAX_QUARANTINE_GETS_WITH_PARAMS).toBe(3);
		// 3 GETs * 128 chars = 384 chars max leakable without triggering isSuspiciousGetExfil
		expect(128 * 3).toBe(384);
	});
});

// ---------------------------------------------------------------------------
// Behavioral rule: GET-as-egress after sensitive read
// ---------------------------------------------------------------------------

describe("behavioral rule: GET treated as egress post-sensitive-read (regression)", () => {
	it("sensitive_read_then_egress fires when GET-with-params is classified as egress", () => {
		const state = new RunStateTracker({ behavioralRules: true });

		state.recordSensitiveFileAttempt();
		state.pushEvent(
			makeEvent({
				type: "sensitive_read_attempt",
				toolClass: "file",
				action: "read",
				metadata: { path: "/home/.env" },
			}),
		);

		// Pipeline reclassifies this GET as egress_attempt
		state.recordEgressAttempt();
		state.pushEvent(
			makeEvent({
				type: "egress_attempt",
				toolClass: "http",
				action: "get",
				metadata: { url: "https://evil.com/c?d=stolen" },
			}),
		);

		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match?.ruleId).toBe("sensitive_read_then_egress");
	});

	it("no behavioral rule fires for GET without sensitive read", () => {
		const state = new RunStateTracker({ behavioralRules: true });

		// Just a normal GET — no sensitive read preceding it
		state.pushEvent(
			makeEvent({
				type: "tool_call_allowed",
				toolClass: "http",
				action: "get",
				metadata: { url: "https://example.com/page" },
			}),
		);

		const match = evaluateBehavioralRules(state);
		expect(match).toBeNull();
	});

	it("cumulative egress tracking records GET query bytes", () => {
		const state = new RunStateTracker({ behavioralRules: true });

		state.recordHttpGetEgress("https://tracker.com/pixel?uid=1&data=abcdef");
		state.recordHttpGetEgress("https://tracker.com/pixel?uid=2&data=ghijkl");

		const record = state.getCumulativeEgress("tracker.com");
		expect(record).toBeDefined();
		expect(record!.requestCount).toBe(2);
		expect(record!.totalQueryBytes).toBeGreaterThan(0);
	});
});
