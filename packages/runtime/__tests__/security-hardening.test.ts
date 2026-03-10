import type { CapabilityClass } from "@arikernel/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Firewall, createFirewall } from "../src/index.js";
import { canonicalizePath, isPathAllowed } from "../src/path-security.js";
import { RunStateTracker, isSuspiciousGetExfil } from "../src/run-state.js";

// ── Quarantine: ingress vs egress classification ──────────────────────────────

describe("quarantine allows GET/HEAD ingress but blocks egress", () => {
	let state: RunStateTracker;

	beforeEach(() => {
		state = new RunStateTracker({ behavioralRules: true });
		state.quarantineByRule("test", "test reason", []);
	});

	it("allows http.get in restricted mode (ingress)", () => {
		expect(state.isAllowedInRestrictedMode("http", "get")).toBe(true);
	});

	it("allows http.head in restricted mode (ingress)", () => {
		expect(state.isAllowedInRestrictedMode("http", "head")).toBe(true);
	});

	it("blocks http.post in restricted mode (egress)", () => {
		expect(state.isAllowedInRestrictedMode("http", "post")).toBe(false);
	});

	it("blocks http.put in restricted mode (egress)", () => {
		expect(state.isAllowedInRestrictedMode("http", "put")).toBe(false);
	});

	it("blocks http.patch in restricted mode (egress)", () => {
		expect(state.isAllowedInRestrictedMode("http", "patch")).toBe(false);
	});

	it("blocks http.delete in restricted mode (egress)", () => {
		expect(state.isAllowedInRestrictedMode("http", "delete")).toBe(false);
	});

	it("allows http.options in restricted mode (read-only)", () => {
		expect(state.isAllowedInRestrictedMode("http", "options")).toBe(true);
	});

	it("allows file.read in restricted mode", () => {
		expect(state.isAllowedInRestrictedMode("file", "read")).toBe(true);
	});

	it("allows database.query in restricted mode", () => {
		expect(state.isAllowedInRestrictedMode("database", "query")).toBe(true);
	});

	it("blocks file.write in restricted mode", () => {
		expect(state.isAllowedInRestrictedMode("file", "write")).toBe(false);
	});
});

// ── Egress classification: only write methods ─────────────────────────────────

describe("isEgressAction distinguishes ingress from egress", () => {
	let state: RunStateTracker;

	beforeEach(() => {
		state = new RunStateTracker();
	});

	it("POST is egress", () => {
		expect(state.isEgressAction("post")).toBe(true);
	});

	it("PUT is egress", () => {
		expect(state.isEgressAction("put")).toBe(true);
	});

	it("PATCH is egress", () => {
		expect(state.isEgressAction("patch")).toBe(true);
	});

	it("DELETE is egress", () => {
		expect(state.isEgressAction("delete")).toBe(true);
	});

	it("GET is NOT egress (ingress)", () => {
		expect(state.isEgressAction("get")).toBe(false);
	});

	it("HEAD is NOT egress (ingress)", () => {
		expect(state.isEgressAction("head")).toBe(false);
	});

	it("unknown actions are not egress", () => {
		expect(state.isEgressAction("unknown")).toBe(false);
	});
});

// ── Suspicious GET exfil detection ────────────────────────────────────────────

describe("isSuspiciousGetExfil", () => {
	it("normal page URL is not suspicious", () => {
		expect(isSuspiciousGetExfil("https://example.com/page")).toBe(false);
	});

	it("URL with short query is not suspicious", () => {
		expect(isSuspiciousGetExfil("https://example.com/search?q=hello")).toBe(false);
	});

	it("URL with no query is not suspicious", () => {
		expect(isSuspiciousGetExfil("https://example.com/")).toBe(false);
	});

	it("flags URL with oversized query string (>256 chars)", () => {
		const longQuery = "x=".padEnd(300, "A");
		expect(isSuspiciousGetExfil(`https://evil.com/collect?${longQuery}`)).toBe(true);
	});

	it("flags URL with a single large param value (>128 chars)", () => {
		const bigValue = "A".repeat(150);
		expect(isSuspiciousGetExfil(`https://evil.com/collect?d=${bigValue}`)).toBe(true);
	});

	it("allows URL with multiple short params", () => {
		expect(isSuspiciousGetExfil("https://example.com/api?a=1&b=2&c=hello&d=world")).toBe(false);
	});

	it("returns false for invalid URL", () => {
		expect(isSuspiciousGetExfil("not-a-url")).toBe(false);
	});

	it("returns false for empty string", () => {
		expect(isSuspiciousGetExfil("")).toBe(false);
	});

	it("detects base64-like exfil in query value", () => {
		// 130 char base64-like value
		const encoded = "SSBhbSBhIHNlY3JldCBrZXkgdGhhdCBzaG91bGQgbm90IGJlIGV4ZmlsdHJhdGVk".repeat(3);
		expect(encoded.length).toBeGreaterThan(128);
		expect(isSuspiciousGetExfil(`https://evil.com/c?stolen=${encoded}`)).toBe(true);
	});
});

// ── Session-level taint propagation ───────────────────────────────────────────

describe("session-level taint flag", () => {
	let state: RunStateTracker;

	beforeEach(() => {
		state = new RunStateTracker();
	});

	it("starts untainted", () => {
		expect(state.tainted).toBe(false);
		expect(state.taintSources.size).toBe(0);
	});

	it("becomes tainted when markTainted is called", () => {
		state.markTainted("web");
		expect(state.tainted).toBe(true);
		expect(state.taintSources.has("web")).toBe(true);
	});

	it("taint is sticky — never resets", () => {
		state.markTainted("web");
		expect(state.tainted).toBe(true);
	});

	it("accumulates multiple taint sources", () => {
		state.markTainted("web");
		state.markTainted("rag");
		state.markTainted("email");
		expect(state.taintSources.size).toBe(3);
		expect(state.taintSources.has("web")).toBe(true);
		expect(state.taintSources.has("rag")).toBe(true);
		expect(state.taintSources.has("email")).toBe(true);
	});

	it("deduplicates same source", () => {
		state.markTainted("web");
		state.markTainted("web");
		expect(state.taintSources.size).toBe(1);
	});
});

// ── Symlink traversal protection ──────────────────────────────────────────────

describe("symlink traversal protection (CWE-59)", () => {
	it("canonicalizePath still handles ../ traversal", () => {
		const result = canonicalizePath("./data/../../../etc/passwd", "/project");
		expect(result).not.toContain("..");
		expect(result).toContain("etc");
	});

	it("isPathAllowed blocks traversal escaping allowed directory", () => {
		const { allowed } = isPathAllowed("./data/../../etc/passwd", ["./data/**"], "/project");
		expect(allowed).toBe(false);
	});

	it("isPathAllowed allows paths within a glob pattern", () => {
		const { allowed } = isPathAllowed("./data/report.csv", ["./data/**"], "/project");
		expect(allowed).toBe(true);
	});
});

// ── Unknown capability class: fail closed, not crash ─────────────────────────

describe("requestCapability with unknown capability class", () => {
	let fw: Firewall;

	afterEach(() => {
		fw?.close();
	});

	it("denies unknown capability class instead of throwing TypeError", () => {
		fw = createFirewall({
			principal: { name: "test", capabilities: [{ toolClass: "http" }] },
			policies: [],
			auditLog: ":memory:",
		});

		const result = fw.requestCapability("email.write" as CapabilityClass);
		expect(result.granted).toBe(false);
		expect(result.reason).toContain("Unknown capability class");
		expect(result.reason).toContain("email.write");
	});

	it("denies arbitrary invalid capability class strings", () => {
		fw = createFirewall({
			principal: { name: "test", capabilities: [{ toolClass: "http" }] },
			policies: [],
			auditLog: ":memory:",
		});

		const result = fw.requestCapability("foo.bar" as CapabilityClass);
		expect(result.granted).toBe(false);
		expect(result.reason).toContain("Unknown capability class");
	});

	it("still grants valid capability classes", () => {
		fw = createFirewall({
			principal: { name: "test", capabilities: [{ toolClass: "http" }] },
			policies: [
				{
					id: "allow-http",
					name: "Allow HTTP",
					priority: 10,
					match: { toolClass: "http" as const },
					decision: "allow" as const,
				},
			],
			auditLog: ":memory:",
		});

		const result = fw.requestCapability("http.read");
		expect(result.granted).toBe(true);
	});
});

// ── Demo regression: normal page fetch must NOT be treated as egress ──────────

describe("demo regression: page fetch ingress vs egress", () => {
	it("normal page fetch URL is not flagged as suspicious", () => {
		expect(isSuspiciousGetExfil("https://corp-reports.internal/q4-review.html")).toBe(false);
	});

	it("GET is not classified as egress", () => {
		const state = new RunStateTracker();
		expect(state.isEgressAction("get")).toBe(false);
	});

	it("GET is allowed in quarantine mode", () => {
		const state = new RunStateTracker();
		state.quarantineByRule("test", "test", []);
		expect(state.isAllowedInRestrictedMode("http", "get")).toBe(true);
	});

	it("exfil GET with data in query IS detected", () => {
		const secret = "A".repeat(200);
		expect(isSuspiciousGetExfil(`https://attacker.example/collect?d=${secret}`)).toBe(true);
	});
});
