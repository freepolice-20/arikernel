import { describe, expect, it } from "vitest";
import { runSimulation } from "../src/runner.js";

describe("runSimulation (all built-in scenarios)", () => {
	it("runs all scenarios and every attack is correctly handled", async () => {
		const results = await runSimulation();
		expect(results.length).toBeGreaterThan(0);

		const failed = results.filter((r) => !r.passed);
		if (failed.length > 0) {
			const names = failed.map((r) => `${r.scenario.name}: expected ${r.scenario.expectedVerdict}, got ${r.actualVerdict}`);
			throw new Error(`Failed scenarios:\n${names.join("\n")}`);
		}

		expect(failed.length).toBe(0);
	});

	it("includes SSRF, filesystem traversal, and tool escalation scenarios", async () => {
		const results = await runSimulation();
		const names = results.map((r) => r.scenario.name);

		// Verify new scenario categories are included
		expect(names.some((n) => n.includes("SSRF"))).toBe(true);
		expect(names.some((n) => n.includes("traversal") || n.includes("Path"))).toBe(true);
		expect(names.some((n) => n.includes("escalation") || n.includes("without capability"))).toBe(true);
	});
});
