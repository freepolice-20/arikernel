import type { TaintLabel } from "@arikernel/core";
import { describe, expect, it } from "vitest";
import { ControlPlaneAuditStore } from "../src/audit-store.js";
import { GlobalTaintRegistry } from "../src/taint-registry.js";

function makeTaint(source: TaintLabel["source"], origin: string): TaintLabel {
	return {
		source,
		origin,
		confidence: 0.9,
		addedAt: new Date().toISOString(),
	};
}

describe("GlobalTaintRegistry", () => {
	it("registers and queries taint by resource", () => {
		const registry = new GlobalTaintRegistry();
		const label = makeTaint("web", "https://evil.com");

		registry.register("agent-1", "run-1", [label], ["/tmp/data.json"]);

		const result = registry.queryResource("/tmp/data.json");
		expect(result).toHaveLength(1);
		expect(result[0].origin).toBe("https://evil.com");
	});

	it("returns empty array for unknown resource", () => {
		const registry = new GlobalTaintRegistry();
		expect(registry.queryResource("unknown")).toEqual([]);
	});

	it("registers taint by principal run", () => {
		const registry = new GlobalTaintRegistry();
		const label = makeTaint("rag", "doc-123");

		registry.register("agent-1", "run-1", [label]);

		const result = registry.queryRun("agent-1", "run-1");
		expect(result).toHaveLength(1);
		expect(result[0].source).toBe("rag");
	});

	it("deduplicates labels by source:origin", () => {
		const registry = new GlobalTaintRegistry();
		const label = makeTaint("web", "same-origin");

		registry.register("agent-1", "run-1", [label]);
		registry.register("agent-1", "run-1", [label]); // duplicate

		const result = registry.queryRun("agent-1", "run-1");
		expect(result).toHaveLength(1);
	});

	it("correlates cross-agent taint on shared resources", () => {
		const registry = new GlobalTaintRegistry();
		const taintA = makeTaint("web", "injected-payload");
		const sharedFile = "/shared/data.csv";

		// Agent A contaminates a shared resource
		registry.register("agent-a", "run-1", [taintA], [sharedFile]);

		// Agent B queries the same resource — sees Agent A's contamination
		const crossTaint = registry.queryResource(sharedFile);
		expect(crossTaint).toHaveLength(1);
		expect(crossTaint[0].origin).toBe("injected-payload");
	});

	it("tracks resource and run counts", () => {
		const registry = new GlobalTaintRegistry();

		registry.register("a", "r1", [makeTaint("web", "x")], ["/foo"]);
		registry.register("b", "r2", [makeTaint("rag", "y")], ["/bar"]);

		expect(registry.resourceCount).toBe(2);
		expect(registry.runCount).toBe(2);
	});

	it("skips registration when labels are empty", () => {
		const registry = new GlobalTaintRegistry();
		registry.register("agent-1", "run-1", [], ["/resource"]);

		expect(registry.resourceCount).toBe(0);
		expect(registry.runCount).toBe(0);
	});
});

describe("GlobalTaintRegistry — SQLite persistence (NF-03)", () => {
	it("persists taint labels to the audit store on register()", () => {
		const store = new ControlPlaneAuditStore(":memory:");
		const registry = new GlobalTaintRegistry(store);
		const label = makeTaint("web", "https://evil.com");

		registry.register("agent-1", "run-1", [label], ["/shared/data.json"]);

		const events = store.allTaintEvents();
		// One run-level row + one resource-level row = 2
		expect(events.length).toBe(2);
		expect(events.some((e) => e.resource_id === null)).toBe(true);
		expect(events.some((e) => e.resource_id === "/shared/data.json")).toBe(true);
		expect(
			events.every((e) => e.label_source === "web" && e.label_origin === "https://evil.com"),
		).toBe(true);

		store.close();
	});

	it("reloads taint state from the store on construction", () => {
		const store = new ControlPlaneAuditStore(":memory:");

		// Seed the store manually
		store.recordTaintEvent("agent-1", "run-1", "web", "injected-payload", null);
		store.recordTaintEvent("agent-1", "run-1", "web", "injected-payload", "/shared/data.csv");

		// New registry instance reads from the existing store
		const registry = new GlobalTaintRegistry(store);

		expect(registry.runCount).toBe(1);
		expect(registry.resourceCount).toBe(1);
		expect(registry.queryRun("agent-1", "run-1")).toHaveLength(1);
		expect(registry.queryResource("/shared/data.csv")).toHaveLength(1);

		store.close();
	});

	it("deduplicates on re-registration of the same label via INSERT OR IGNORE", () => {
		const store = new ControlPlaneAuditStore(":memory:");
		const registry = new GlobalTaintRegistry(store);
		const label = makeTaint("rag", "doc-123");

		registry.register("agent-1", "run-1", [label]);
		registry.register("agent-1", "run-1", [label]); // duplicate

		const events = store.allTaintEvents();
		// INSERT OR IGNORE means only 1 row persisted
		expect(events.length).toBe(1);
		// In-memory dedup still works
		expect(registry.queryRun("agent-1", "run-1")).toHaveLength(1);

		store.close();
	});

	it("survives restart: new registry loaded from same store reflects prior state", () => {
		const store = new ControlPlaneAuditStore(":memory:");
		const registry1 = new GlobalTaintRegistry(store);
		registry1.register("agent-a", "run-1", [makeTaint("web", "attack")], ["/important.txt"]);

		// Simulate restart by creating a fresh registry from the same store
		const registry2 = new GlobalTaintRegistry(store);
		expect(registry2.queryResource("/important.txt")).toHaveLength(1);
		expect(registry2.queryResource("/important.txt")[0].origin).toBe("attack");

		store.close();
	});
});
