import { describe, expect, it, vi } from "vitest";
import type { AuditEvent } from "@arikernel/core";
import { CrossPrincipalCorrelator, type CrossPrincipalAlert } from "../src/correlator.js";

function makeEvent(overrides: Partial<AuditEvent> = {}): AuditEvent {
	return {
		id: "evt-1",
		runId: "run-1",
		principalId: "p1",
		timestamp: new Date().toISOString(),
		type: "tool_call",
		toolClass: "http",
		action: "get",
		...overrides,
	} as AuditEvent;
}

describe("CrossPrincipalCorrelator", () => {
	it("CP-1: fires for cross-principal sensitive-read → shared-write → shared-read → egress", () => {
		const correlator = new CrossPrincipalCorrelator({ windowMs: 60_000 });
		const alerts: CrossPrincipalAlert[] = [];
		correlator.onAlert((a) => alerts.push(a));

		// Agent A reads sensitive file
		correlator.ingest(
			makeEvent({
				toolClass: "file",
				action: "read",
				parameters: { path: "/home/user/.ssh/id_rsa" },
			}),
			"agent-A",
		);

		// Agent A writes to shared DB
		correlator.ingest(
			makeEvent({ toolClass: "database", action: "insert" }),
			"agent-A",
		);

		// Agent B reads from shared DB
		correlator.ingest(
			makeEvent({ toolClass: "database", action: "query" }),
			"agent-B",
		);

		// Agent B egresses — should trigger CP-1
		correlator.ingest(
			makeEvent({ toolClass: "http", action: "post" }),
			"agent-B",
		);

		expect(alerts).toHaveLength(1);
		expect(alerts[0].ruleId).toBe("cross-principal-sensitive-exfil");
		expect(alerts[0].severity).toBe("high");
		expect(alerts[0].principals).toContain("agent-A");
		expect(alerts[0].principals).toContain("agent-B");
	});

	it("same-principal events do NOT fire CP-1", () => {
		const correlator = new CrossPrincipalCorrelator({ windowMs: 60_000 });
		const alerts: CrossPrincipalAlert[] = [];
		correlator.onAlert((a) => alerts.push(a));

		// Same agent does everything
		correlator.ingest(
			makeEvent({
				toolClass: "file",
				action: "read",
				parameters: { path: "/home/.env" },
			}),
			"agent-A",
		);
		correlator.ingest(
			makeEvent({ toolClass: "database", action: "insert" }),
			"agent-A",
		);
		correlator.ingest(
			makeEvent({ toolClass: "database", action: "query" }),
			"agent-A",
		);
		correlator.ingest(
			makeEvent({ toolClass: "http", action: "post" }),
			"agent-A",
		);

		// CP-1 should NOT fire (same principal)
		const cp1Alerts = alerts.filter((a) => a.ruleId === "cross-principal-sensitive-exfil");
		expect(cp1Alerts).toHaveLength(0);
	});

	it("events outside time window do not trigger", () => {
		const correlator = new CrossPrincipalCorrelator({ windowMs: 100 }); // 100ms window
		const alerts: CrossPrincipalAlert[] = [];
		correlator.onAlert((a) => alerts.push(a));

		const oldTimestamp = new Date(Date.now() - 200).toISOString(); // 200ms ago

		correlator.ingest(
			makeEvent({
				toolClass: "file",
				action: "read",
				parameters: { path: "/home/.ssh/id_rsa" },
				timestamp: oldTimestamp,
			}),
			"agent-A",
		);
		correlator.ingest(
			makeEvent({ toolClass: "database", action: "insert", timestamp: oldTimestamp }),
			"agent-A",
		);
		correlator.ingest(
			makeEvent({ toolClass: "database", action: "query" }),
			"agent-B",
		);
		correlator.ingest(
			makeEvent({ toolClass: "http", action: "post" }),
			"agent-B",
		);

		const cp1Alerts = alerts.filter((a) => a.ruleId === "cross-principal-sensitive-exfil");
		expect(cp1Alerts).toHaveLength(0);
	});

	it("CP-2: derived-sensitive taint egress fires medium alert", () => {
		const correlator = new CrossPrincipalCorrelator();
		const alerts: CrossPrincipalAlert[] = [];
		correlator.onAlert((a) => alerts.push(a));

		correlator.ingest(
			makeEvent({
				toolClass: "http",
				action: "post",
				taintSources: ["derived-sensitive"],
			}),
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
				toolClass: "http",
				action: "put",
				taintSources: ["derived-sensitive"],
			}),
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
