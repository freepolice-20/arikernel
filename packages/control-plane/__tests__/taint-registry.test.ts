import type { TaintLabel } from "@arikernel/core";
import { describe, expect, it } from "vitest";
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
