/**
 * Taint enforcement tests.
 *
 * Proves that:
 * 1. Tools cannot silently drop taint metadata
 * 2. Run-level taint state persists independently of tool metadata
 * 3. Tainted content triggers behavioral rules
 * 4. Subsequent tool calls inherit accumulated taint even without explicit labels
 */

import { unlinkSync } from "node:fs";
import { resolve } from "node:path";
import { ToolCallDeniedError } from "@arikernel/core";
import type { TaintLabel } from "@arikernel/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Firewall, createFirewall } from "../src/index.js";
import { evaluateBehavioralRules } from "../src/behavioral-rules.js";
import { RunStateTracker } from "../src/run-state.js";

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
	const path = resolve(import.meta.dirname, `test-taint-${name}-${Date.now()}.db`);
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

function makeFirewall(name: string): Firewall {
	const fw = createFirewall({
		principal: {
			name: "test-agent",
			capabilities: [
				{
					toolClass: "http",
					actions: ["get", "post"],
					constraints: { allowedHosts: ["*"] },
				},
				{ toolClass: "file", actions: ["read"], constraints: { allowedPaths: ["./**"] } },
				{ toolClass: "database", actions: ["query", "exec"] },
			],
		},
		policies: POLICY_PATH,
		auditLog: auditPath(name),
		runStatePolicy: { maxDeniedSensitiveActions: 5, behavioralRules: true },
	});

	// Register stub executors that return empty taintLabels (simulating tools that try to drop taint)
	fw.registerExecutor({
		toolClass: "http",
		async execute(toolCall) {
			return {
				callId: toolCall.id,
				success: true,
				data: { body: "response from " + toolCall.parameters.url },
				durationMs: 10,
				taintLabels: [], // deliberately empty — tool tries to clear taint
			};
		},
	});
	fw.registerExecutor({
		toolClass: "file",
		async execute(toolCall) {
			return {
				callId: toolCall.id,
				success: true,
				data: { content: "file contents" },
				durationMs: 5,
				taintLabels: [], // deliberately empty
			};
		},
	});
	fw.registerExecutor({
		toolClass: "database",
		async execute(toolCall) {
			return {
				callId: toolCall.id,
				success: true,
				data: { rows: [] },
				durationMs: 5,
				taintLabels: [], // deliberately empty
			};
		},
	});

	return fw;
}

function webTaint(origin = "evil.com"): TaintLabel[] {
	return [
		{
			source: "web",
			origin,
			confidence: 0.9,
			addedAt: new Date().toISOString(),
		},
	];
}

// ── Tool cannot drop taint metadata ──────────────────────────────────

describe("tool cannot drop taint metadata", () => {
	let fw: Firewall;

	beforeEach(() => {
		fw = makeFirewall("drop-taint");
	});

	afterEach(() => {
		fw.close();
	});

	it("first tainted call produces taint labels even when tool returns empty", async () => {
		const grant = fw.requestCapability("http.read");
		expect(grant.granted).toBe(true);

		const result = await fw.execute({
			toolClass: "http",
			action: "get",
			parameters: { url: "http://example.com" },
			taintLabels: webTaint(),
			grantId: grant.grant!.id,
		});

		// Even though the stub executor returned empty taintLabels,
		// the pipeline propagated the input web taint
		expect(result.taintLabels.length).toBeGreaterThan(0);
		expect(result.taintLabels.some((l) => l.source === "web")).toBe(true);
	});

	it("subsequent call without taintLabels still carries run-level taint", async () => {
		// Call 1: tainted web input
		const grant1 = fw.requestCapability("http.read");
		await fw.execute({
			toolClass: "http",
			action: "get",
			parameters: { url: "http://evil.com" },
			taintLabels: webTaint(),
			grantId: grant1.grant!.id,
		});

		// Call 2: no explicit taintLabels — agent "forgot" to include them
		const grant2 = fw.requestCapability("file.read");
		const result = await fw.execute({
			toolClass: "file",
			action: "read",
			parameters: { path: "./readme.md" },
			// no taintLabels — should still get run-level taint
			grantId: grant2.grant!.id,
		});

		// The kernel must inject accumulated run-level taint
		expect(result.taintLabels.length).toBeGreaterThan(0);
		expect(result.taintLabels.some((l) => l.source === "web")).toBe(true);
	});

	it("tool returning empty taintLabels does not clear run-level taint state", async () => {
		// Call 1: tainted
		const grant1 = fw.requestCapability("http.read");
		await fw.execute({
			toolClass: "http",
			action: "get",
			parameters: { url: "http://evil.com" },
			taintLabels: webTaint(),
			grantId: grant1.grant!.id,
		});

		// Verify run-level taint state is set
		expect(fw.taintState.tainted).toBe(true);
		expect(fw.taintState.sources).toContain("web");
		expect(fw.taintState.labels.length).toBeGreaterThan(0);

		// Call 2: tool returns empty taintLabels
		const grant2 = fw.requestCapability("http.read");
		await fw.execute({
			toolClass: "http",
			action: "get",
			parameters: { url: "http://clean-site.com" },
			// no taintLabels
			grantId: grant2.grant!.id,
		});

		// Run-level taint must still be set (sticky)
		expect(fw.taintState.tainted).toBe(true);
		expect(fw.taintState.sources).toContain("web");
		expect(fw.taintState.labels.length).toBeGreaterThan(0);
	});

	it("taintState is initially clean", () => {
		expect(fw.taintState.tainted).toBe(false);
		expect(fw.taintState.sources).toEqual([]);
		expect(fw.taintState.labels).toEqual([]);
	});

	it("taintState accumulates multiple taint sources", async () => {
		const grant1 = fw.requestCapability("http.read");
		await fw.execute({
			toolClass: "http",
			action: "get",
			parameters: { url: "http://site-a.com" },
			taintLabels: webTaint("site-a.com"),
			grantId: grant1.grant!.id,
		});

		const grant2 = fw.requestCapability("http.read");
		await fw.execute({
			toolClass: "http",
			action: "get",
			parameters: { url: "http://site-b.com" },
			taintLabels: [
				{
					source: "rag",
					origin: "vector-db",
					confidence: 0.8,
					addedAt: new Date().toISOString(),
				},
			],
			grantId: grant2.grant!.id,
		});

		expect(fw.taintState.tainted).toBe(true);
		expect(fw.taintState.sources).toContain("web");
		expect(fw.taintState.sources).toContain("rag");
		expect(fw.taintState.labels.length).toBeGreaterThanOrEqual(2);
	});
});

// ── Tainted content triggers behavioral rules ────────────────────────

describe("tainted content triggers behavioral rules", () => {
	it("web taint followed by shell exec matches web_taint_sensitive_probe", () => {
		const state = new RunStateTracker({ behavioralRules: true });
		state.pushEvent({
			timestamp: new Date().toISOString(),
			type: "taint_observed",
			taintSources: ["web"],
		});
		state.pushEvent({
			timestamp: new Date().toISOString(),
			type: "tool_call_allowed",
			toolClass: "shell",
			action: "exec",
		});
		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match?.ruleId).toBe("web_taint_sensitive_probe");
	});

	it("web taint followed by egress attempt matches sensitive probe", () => {
		const state = new RunStateTracker({ behavioralRules: true });
		state.pushEvent({
			timestamp: new Date().toISOString(),
			type: "taint_observed",
			taintSources: ["web"],
		});
		state.pushEvent({
			timestamp: new Date().toISOString(),
			type: "egress_attempt",
			toolClass: "http",
			action: "post",
		});
		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match?.ruleId).toBe("web_taint_sensitive_probe");
	});

	it("tainted database write triggers tainted_database_write rule", () => {
		const state = new RunStateTracker({ behavioralRules: true });
		state.pushEvent({
			timestamp: new Date().toISOString(),
			type: "taint_observed",
			taintSources: ["email"],
		});
		state.pushEvent({
			timestamp: new Date().toISOString(),
			type: "tool_call_allowed",
			toolClass: "database",
			action: "exec",
		});
		const match = evaluateBehavioralRules(state);
		expect(match).not.toBeNull();
		expect(match?.ruleId).toBe("tainted_database_write");
	});

	it("tainted input triggers quarantine on shell exec via full pipeline", async () => {
		const fw = makeFirewall("taint-quarantine");
		try {
			// Register a shell executor so it doesn't fail on missing executor
			fw.registerExecutor({
				toolClass: "shell",
				async execute(toolCall) {
					return {
						callId: toolCall.id,
						success: true,
						data: null,
						durationMs: 1,
						taintLabels: [],
					};
				},
			});

			// Step 1: web-tainted HTTP GET (allowed)
			const grant1 = fw.requestCapability("http.read");
			await fw.execute({
				toolClass: "http",
				action: "get",
				parameters: { url: "http://evil.com/payload" },
				taintLabels: webTaint(),
				grantId: grant1.grant!.id,
			});

			// Step 2: attempt shell.exec — should be denied by policy (tainted shell)
			// The safe-defaults policy denies shell with web taint
			const grant2 = fw.requestCapability("shell.exec");
			// Capability issuance itself may be denied for shell with taint
			if (grant2.granted) {
				await expect(
					fw.execute({
						toolClass: "shell",
						action: "exec",
						parameters: { command: "echo hello" },
						grantId: grant2.grant!.id,
					}),
				).rejects.toThrow(ToolCallDeniedError);
			} else {
				// Shell capability denied due to taint risk — correct behavior
				expect(grant2.reason).toBeTruthy();
			}
		} finally {
			fw.close();
		}
	});
});

// ── RunStateTracker taint accumulation ──────────────────────────────

describe("RunStateTracker taint accumulation", () => {
	it("accumulateTaintLabels stores labels and marks tainted", () => {
		const state = new RunStateTracker();
		expect(state.taintState.tainted).toBe(false);

		state.accumulateTaintLabels(webTaint("example.com"));

		expect(state.taintState.tainted).toBe(true);
		expect(state.taintState.sources).toContain("web");
		expect(state.taintState.labels).toHaveLength(1);
		expect(state.taintState.labels[0].origin).toBe("example.com");
	});

	it("deduplicates labels by source:origin", () => {
		const state = new RunStateTracker();
		state.accumulateTaintLabels(webTaint("example.com"));
		state.accumulateTaintLabels(webTaint("example.com"));

		expect(state.taintState.labels).toHaveLength(1);
	});

	it("accumulates labels from different origins", () => {
		const state = new RunStateTracker();
		state.accumulateTaintLabels(webTaint("site-a.com"));
		state.accumulateTaintLabels(webTaint("site-b.com"));

		expect(state.taintState.labels).toHaveLength(2);
		expect(state.taintState.sources).toEqual(["web"]);
	});

	it("taintState snapshot is independent of internal state", () => {
		const state = new RunStateTracker();
		state.accumulateTaintLabels(webTaint("example.com"));

		const snapshot = state.taintState;
		state.accumulateTaintLabels([
			{
				source: "rag",
				origin: "vector-db",
				confidence: 0.8,
				addedAt: new Date().toISOString(),
			},
		]);

		// Snapshot should not be affected by later mutations
		expect(snapshot.labels).toHaveLength(1);
		expect(state.taintState.labels).toHaveLength(2);
	});
});
