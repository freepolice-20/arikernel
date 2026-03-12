import type { AuditEvent } from "@arikernel/core";
import { describe, expect, it, vi } from "vitest";
import { type CrossPrincipalAlert, CrossPrincipalCorrelator } from "../src/correlator.js";

function makeEvent(overrides: Partial<AuditEvent> = {}): AuditEvent {
	const toolCall = {
		id: "tc-1",
		runId: "run-1",
		sequence: 0,
		timestamp: new Date().toISOString(),
		principalId: "p1",
		toolClass: "http",
		action: "get",
		parameters: {},
		taintLabels: [],
		...(overrides as any).toolCall,
	};
	return {
		id: "evt-1",
		runId: "run-1",
		sequence: 0,
		timestamp: new Date().toISOString(),
		principalId: "p1",
		toolCall,
		decision: {
			verdict: "allow",
			matchedRule: null,
			reason: "",
			taintLabels: [],
			timestamp: new Date().toISOString(),
		},
		previousHash: "",
		hash: "",
		...overrides,
	} as AuditEvent;
}

function makeEventWithToolCall(
	toolClass: string,
	action: string,
	parameters: Record<string, unknown> = {},
	extra: Partial<AuditEvent> = {},
): AuditEvent {
	return makeEvent({
		...extra,
		toolCall: {
			id: "tc-1",
			runId: "run-1",
			sequence: 0,
			timestamp: extra.timestamp ?? new Date().toISOString(),
			principalId: "p1",
			toolClass,
			action,
			parameters,
			taintLabels: [],
		},
	} as any);
}

describe("CrossPrincipalCorrelator", () => {
	it("CP-1: fires for cross-principal sensitive-read → shared-write → shared-read → egress (same resource)", () => {
		const correlator = new CrossPrincipalCorrelator({ windowMs: 60_000 });
		const alerts: CrossPrincipalAlert[] = [];
		correlator.onAlert((a) => alerts.push(a));

		// Agent A reads sensitive file
		correlator.ingest(
			makeEventWithToolCall("file", "read", { path: "/home/user/.ssh/id_rsa" }),
			"agent-A",
		);

		// Agent A writes to shared DB table "messages"
		correlator.ingest(
			makeEventWithToolCall("database", "insert", { table: "messages" }),
			"agent-A",
		);

		// Agent B reads from the SAME shared DB table "messages"
		correlator.ingest(makeEventWithToolCall("database", "query", { table: "messages" }), "agent-B");

		// Agent B egresses — should trigger CP-1
		correlator.ingest(makeEventWithToolCall("http", "post"), "agent-B");

		expect(alerts).toHaveLength(1);
		expect(alerts[0].ruleId).toBe("cross-principal-sensitive-exfil");
		expect(alerts[0].severity).toBe("high");
		expect(alerts[0].principals).toContain("agent-A");
		expect(alerts[0].principals).toContain("agent-B");
	});

	it("CP-1: does NOT fire when write and read target different resources", () => {
		const correlator = new CrossPrincipalCorrelator({ windowMs: 60_000 });
		const alerts: CrossPrincipalAlert[] = [];
		correlator.onAlert((a) => alerts.push(a));

		// Agent A reads sensitive file and writes to table "secrets"
		correlator.ingest(
			makeEventWithToolCall("file", "read", { path: "/home/user/.ssh/id_rsa" }),
			"agent-A",
		);
		correlator.ingest(makeEventWithToolCall("database", "insert", { table: "secrets" }), "agent-A");

		// Agent B reads from a DIFFERENT table "public_data"
		correlator.ingest(
			makeEventWithToolCall("database", "query", { table: "public_data" }),
			"agent-B",
		);

		// Agent B egresses — should NOT fire because resources don't match
		correlator.ingest(makeEventWithToolCall("http", "post"), "agent-B");

		const cp1Alerts = alerts.filter((a) => a.ruleId === "cross-principal-sensitive-exfil");
		expect(cp1Alerts).toHaveLength(0);
	});

	it("same-principal events do NOT fire CP-1", () => {
		const correlator = new CrossPrincipalCorrelator({ windowMs: 60_000 });
		const alerts: CrossPrincipalAlert[] = [];
		correlator.onAlert((a) => alerts.push(a));

		correlator.ingest(makeEventWithToolCall("file", "read", { path: "/home/.env" }), "agent-A");
		correlator.ingest(
			makeEventWithToolCall("database", "insert", { table: "messages" }),
			"agent-A",
		);
		correlator.ingest(makeEventWithToolCall("database", "query", { table: "messages" }), "agent-A");
		correlator.ingest(makeEventWithToolCall("http", "post"), "agent-A");

		const cp1Alerts = alerts.filter((a) => a.ruleId === "cross-principal-sensitive-exfil");
		expect(cp1Alerts).toHaveLength(0);
	});

	it("events outside time window do not trigger", () => {
		const correlator = new CrossPrincipalCorrelator({ windowMs: 100 }); // 100ms window
		const alerts: CrossPrincipalAlert[] = [];
		correlator.onAlert((a) => alerts.push(a));

		const oldTimestamp = new Date(Date.now() - 200).toISOString();

		correlator.ingest(
			makeEventWithToolCall(
				"file",
				"read",
				{ path: "/home/.ssh/id_rsa" },
				{ timestamp: oldTimestamp },
			),
			"agent-A",
		);
		correlator.ingest(
			makeEventWithToolCall(
				"database",
				"insert",
				{ table: "messages" },
				{ timestamp: oldTimestamp },
			),
			"agent-A",
		);
		correlator.ingest(makeEventWithToolCall("database", "query", { table: "messages" }), "agent-B");
		correlator.ingest(makeEventWithToolCall("http", "post"), "agent-B");

		const cp1Alerts = alerts.filter((a) => a.ruleId === "cross-principal-sensitive-exfil");
		expect(cp1Alerts).toHaveLength(0);
	});

	it("CP-2: derived-sensitive taint egress fires medium alert", () => {
		const correlator = new CrossPrincipalCorrelator();
		const alerts: CrossPrincipalAlert[] = [];
		correlator.onAlert((a) => alerts.push(a));

		correlator.ingest(
			makeEvent({
				toolCall: {
					id: "tc-1",
					runId: "run-1",
					sequence: 0,
					timestamp: new Date().toISOString(),
					principalId: "agent-C",
					toolClass: "http",
					action: "post",
					parameters: {},
					taintLabels: [
						{
							source: "derived-sensitive",
							origin: "cross-principal:agent-X",
							confidence: 1,
							addedAt: new Date().toISOString(),
						},
					],
				},
			} as any),
			"agent-C",
		);

		expect(alerts).toHaveLength(1);
		expect(alerts[0].ruleId).toBe("derived-sensitive-egress");
		expect(alerts[0].severity).toBe("medium");
		expect(alerts[0].principals).toEqual(["agent-C"]);
	});

	it("alert handler receives correct structure", () => {
		const correlator = new CrossPrincipalCorrelator();
		const handler = vi.fn();
		correlator.onAlert(handler);

		correlator.ingest(
			makeEvent({
				toolCall: {
					id: "tc-1",
					runId: "run-1",
					sequence: 0,
					timestamp: new Date().toISOString(),
					principalId: "agent-D",
					toolClass: "http",
					action: "put",
					parameters: {},
					taintLabels: [
						{
							source: "derived-sensitive",
							origin: "cross-principal:agent-Y",
							confidence: 1,
							addedAt: new Date().toISOString(),
						},
					],
				},
			} as any),
			"agent-D",
		);

		expect(handler).toHaveBeenCalledOnce();
		const alert = handler.mock.calls[0][0] as CrossPrincipalAlert;
		expect(alert.alertId).toBeTruthy();
		expect(alert.timestamp).toBeTruthy();
		expect(alert.events).toHaveLength(1);
		expect(alert.events[0].toolClass).toBe("http");
	});
});
