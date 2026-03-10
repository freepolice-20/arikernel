/**
 * OWASP LLM Top 10 adversarial test suite.
 *
 * Maps AriKernel defenses to OWASP LLM Application categories,
 * testing that the tool-call enforcement layer catches relevant attack patterns.
 */

import { unlinkSync } from "node:fs";
import { resolve } from "node:path";
import { ToolCallDeniedError } from "@arikernel/core";
import { afterEach, describe, expect, it } from "vitest";
import { evaluateBehavioralRules } from "../src/behavioral-rules.js";
import {
	type Firewall,
	RunStateTracker,
	createFirewall,
	createSecretPatternFilter,
} from "../src/index.js";
import type { SecurityEvent } from "../src/run-state.js";

const POLICY_PATH = resolve(
	import.meta.dirname,
	"..",
	"..",
	"..",
	"policies",
	"safe-defaults.yaml",
);
const auditFiles: string[] = [];

function auditPath(name: string): string {
	const path = resolve(import.meta.dirname, `test-owasp-${name}-${Date.now()}.db`);
	auditFiles.push(path);
	return path;
}

afterEach(() => {
	for (const f of auditFiles) {
		try {
			unlinkSync(f);
		} catch {}
	}
	auditFiles.length = 0;
});

function ts(): string {
	return new Date().toISOString();
}

function pushEvents(state: RunStateTracker, events: SecurityEvent[]): void {
	for (const e of events) state.pushEvent(e);
}

function makeFirewall(name: string, threshold = 3): Firewall {
	return createFirewall({
		principal: {
			name: "test-agent",
			capabilities: [
				{
					toolClass: "http",
					actions: ["get", "post"],
					constraints: { allowedHosts: ["httpbin.org"] },
				},
				{ toolClass: "file", actions: ["read"], constraints: { allowedPaths: ["./data/**"] } },
				{ toolClass: "shell", actions: ["exec"] },
				{ toolClass: "database", actions: ["query", "exec"] },
			],
		},
		policies: POLICY_PATH,
		auditLog: auditPath(name),
		runStatePolicy: { maxDeniedSensitiveActions: threshold },
	});
}

// ── LLM01: Prompt Injection (tool-call layer) ──────────────────────

describe("LLM01 — Prompt Injection", () => {
	it("web-tainted input followed by shell exec triggers quarantine", () => {
		const state = new RunStateTracker();
		pushEvents(state, [
			{ timestamp: ts(), type: "taint_observed", taintSources: ["web"] },
			{ timestamp: ts(), type: "tool_call_allowed", toolClass: "shell", action: "exec" },
		]);
		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match?.ruleId).toBe("web_taint_sensitive_probe");
	});

	it("RAG-tainted input followed by file write is blocked by policy", async () => {
		const fw = makeFirewall("llm01-rag");
		try {
			// file.write is not in the principal's capabilities
			await fw.execute({
				toolClass: "file",
				action: "write",
				parameters: { path: "./data/out.txt" },
			});
			expect.unreachable();
		} catch (err) {
			expect(err).toBeInstanceOf(ToolCallDeniedError);
		}
		fw.close();
	});

	it("multi-step: web fetch + taint + DB write triggers quarantine", () => {
		const state = new RunStateTracker();
		pushEvents(state, [
			{ timestamp: ts(), type: "taint_observed", taintSources: ["web"] },
			{ timestamp: ts(), type: "tool_call_allowed", toolClass: "database", action: "exec" },
		]);
		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match?.ruleId).toBe("tainted_database_write");
	});
});

// ── LLM02: Insecure Output Handling ────────────────────────────────

describe("LLM02 — Insecure Output Handling (DLP)", () => {
	const filter = createSecretPatternFilter();
	const tc = {
		id: "tc-1",
		runId: "r-1",
		sequence: 0,
		timestamp: ts(),
		principalId: "test",
		toolClass: "http",
		action: "get",
		parameters: {},
		taintLabels: [],
	};

	it("redacts AWS keys in tool output", () => {
		const result = filter(tc, {
			callId: "tc-1",
			success: true,
			durationMs: 10,
			taintLabels: [],
			data: "config: AKIAIOSFODNN7EXAMPLE",
		});
		expect(result.data).not.toContain("AKIA");
		expect(result.taintLabels.some((t) => t.origin?.startsWith("redacted:"))).toBe(true);
	});

	it("redacts private key material in tool output", () => {
		const result = filter(tc, {
			callId: "tc-1",
			success: true,
			durationMs: 10,
			taintLabels: [],
			data: "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
		});
		expect(result.data).toContain("[REDACTED]");
	});

	it("passes clean output through unchanged", () => {
		const result = filter(tc, {
			callId: "tc-1",
			success: true,
			durationMs: 10,
			taintLabels: [],
			data: "Revenue: $1.2M, Growth: 15%",
		});
		expect(result.data).toBe("Revenue: $1.2M, Growth: 15%");
		expect(result.taintLabels).toHaveLength(0);
	});
});

// ── LLM04: Model Denial of Service ─────────────────────────────────

describe("LLM04 — Denial of Service (threshold quarantine)", () => {
	it("rapid denied requests trigger threshold quarantine", async () => {
		const fw = makeFirewall("llm04", 3);
		const grant = fw.requestCapability("file.read");

		for (const path of ["~/.ssh/id_rsa", "~/.aws/credentials", "/etc/shadow"]) {
			try {
				await fw.execute({
					toolClass: "file",
					action: "read",
					parameters: { path },
					grantId: grant.grant?.id,
				});
			} catch {}
		}

		expect(fw.isRestricted).toBe(true);
		expect(fw.runStateCounters.deniedActions).toBeGreaterThanOrEqual(3);
		fw.close();
	});
});

// ── LLM06: Sensitive Information Disclosure ────────────────────────

describe("LLM06 — Sensitive Information Disclosure", () => {
	it("reading .ssh then POST triggers quarantine", () => {
		const state = new RunStateTracker();
		pushEvents(state, [
			{
				timestamp: ts(),
				type: "sensitive_read_attempt",
				toolClass: "file",
				action: "read",
				metadata: { path: "~/.ssh/id_rsa" },
			},
			{ timestamp: ts(), type: "egress_attempt", toolClass: "http", action: "post" },
		]);
		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match?.ruleId).toBe("sensitive_read_then_egress");
	});

	it("reading .env then external POST triggers quarantine", () => {
		const state = new RunStateTracker();
		pushEvents(state, [
			{
				timestamp: ts(),
				type: "sensitive_read_attempt",
				toolClass: "file",
				action: "read",
				metadata: { path: ".env" },
			},
			{ timestamp: ts(), type: "egress_attempt", toolClass: "http", action: "post" },
		]);
		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match?.ruleId).toBe("sensitive_read_then_egress");
	});

	it("vault query then egress triggers quarantine", () => {
		const state = new RunStateTracker();
		pushEvents(state, [
			{
				timestamp: ts(),
				type: "tool_call_allowed",
				toolClass: "database",
				action: "query",
				metadata: { query: "SELECT api_key FROM secrets" },
			},
			{ timestamp: ts(), type: "egress_attempt", toolClass: "http", action: "post" },
		]);
		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match?.ruleId).toBe("secret_access_then_any_egress");
	});
});

// ── LLM08: Excessive Agency ────────────────────────────────────────

describe("LLM08 — Excessive Agency (capability enforcement)", () => {
	let fw: Firewall;

	afterEach(() => {
		fw?.close();
		fw = undefined as unknown as Firewall;
	});

	it("agent with http.get cannot escalate to shell.exec via execute", async () => {
		fw = makeFirewall("llm08-escalate");
		const httpGrant = fw.requestCapability("http.read");

		// Try to use HTTP grant for shell execution
		try {
			await fw.execute({
				toolClass: "shell",
				action: "exec",
				parameters: { command: "whoami" },
				grantId: httpGrant.grant?.id,
			});
			expect.unreachable();
		} catch (err) {
			expect(err).toBeInstanceOf(ToolCallDeniedError);
		}
	});

	it("file.read token cannot be used for file.write", async () => {
		fw = makeFirewall("llm08-token");
		const readGrant = fw.requestCapability("file.read");

		try {
			await fw.execute({
				toolClass: "file",
				action: "write",
				parameters: { path: "./data/out.txt", content: "pwned" },
				grantId: readGrant.grant?.id,
			});
			expect.unreachable();
		} catch (err) {
			expect(err).toBeInstanceOf(ToolCallDeniedError);
		}
	});

	it("protected action without grant is denied", async () => {
		fw = makeFirewall("llm08-nogrant");

		try {
			await fw.execute({
				toolClass: "http",
				action: "get",
				parameters: { url: "https://httpbin.org/get" },
				// no grantId
			});
			expect.unreachable();
		} catch (err) {
			expect(err).toBeInstanceOf(ToolCallDeniedError);
		}
	});

	it("capability denied then escalation triggers quarantine", () => {
		const state = new RunStateTracker();
		pushEvents(state, [
			{ timestamp: ts(), type: "capability_denied", toolClass: "http" },
			{ timestamp: ts(), type: "capability_requested", toolClass: "shell" },
		]);
		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match?.ruleId).toBe("denied_capability_then_escalation");
	});
});

// ── LLM07: Insecure Plugin Design (MCP-related patterns) ──────────

describe("LLM07 — Insecure Plugin Design (behavioral patterns)", () => {
	it("tainted input + database write = quarantine", () => {
		const state = new RunStateTracker();
		pushEvents(state, [
			{ timestamp: ts(), type: "taint_observed", taintSources: ["web"] },
			{ timestamp: ts(), type: "tool_call_allowed", toolClass: "database", action: "mutate" },
		]);
		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match?.ruleId).toBe("tainted_database_write");
	});

	it("tainted shell with long command = quarantine", () => {
		const state = new RunStateTracker();
		pushEvents(state, [
			{ timestamp: ts(), type: "taint_observed", taintSources: ["email"] },
			{
				timestamp: ts(),
				type: "tool_call_allowed",
				toolClass: "shell",
				action: "exec",
				metadata: { commandLength: 200 },
			},
		]);
		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		// Rule 1 catches taint→shell first; rule 5 would also match but rule 1 has priority
		expect(match?.ruleId).toBe("web_taint_sensitive_probe");
	});
});
