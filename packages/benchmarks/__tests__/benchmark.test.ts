import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { aggregateMetrics } from "../src/metrics.js";
import { SCENARIOS, benchmark } from "../src/runner.js";

function tempDir(): string {
	return mkdtempSync(join(tmpdir(), "arikernel-bench-"));
}

const dirs: string[] = [];

afterEach(() => {
	for (const d of dirs) {
		try {
			rmSync(d, { recursive: true, force: true });
		} catch {
			/* ignore */
		}
	}
	dirs.length = 0;
});

describe("SCENARIOS registry", () => {
	it("exports 13 scenarios", () => {
		expect(SCENARIOS).toHaveLength(13);
	});

	it("each scenario has unique id", () => {
		const ids = SCENARIOS.map((s) => s.id);
		expect(new Set(ids).size).toBe(SCENARIOS.length);
	});

	it("covers all attack categories", () => {
		const categories = new Set(SCENARIOS.map((s) => s.category));
		expect(categories).toContain("prompt_injection");
		expect(categories).toContain("tool_escalation");
		expect(categories).toContain("data_exfiltration");
		expect(categories).toContain("filesystem_traversal");
		expect(categories).toContain("database_escalation");
		expect(categories).toContain("taint_chain");
	});
});

describe("benchmark — all attacks blocked", () => {
	it("blocks all 13 attack scenarios", async () => {
		const dir = tempDir();
		dirs.push(dir);

		const { results, summary } = await benchmark(dir);

		expect(results).toHaveLength(13);

		for (const r of results) {
			expect(r.verdict).toBe("BLOCKED");
			expect(r.enforcementMechanism).toBeTruthy();
			expect(r.runId).toBeTruthy();
			expect(r.durationMs).toBeGreaterThanOrEqual(0);
		}

		expect(summary.attacksBlocked).toBe(13);
		expect(summary.attacksBlockedPct).toBe(100);
	});

	it("reports correct enforcement mechanisms", async () => {
		const dir = tempDir();
		dirs.push(dir);

		const { results } = await benchmark(dir);

		const mechanisms = new Set(results.map((r) => r.enforcementMechanism));
		// Should use multiple enforcement types
		expect(mechanisms.size).toBeGreaterThanOrEqual(3);
	});

	it("per-category breakdown is complete", async () => {
		const dir = tempDir();
		dirs.push(dir);

		const { summary } = await benchmark(dir);

		for (const [, counts] of Object.entries(summary.byCategory)) {
			expect(counts.blocked).toBe(counts.total);
		}
	});
});

describe("individual scenarios", () => {
	it("prompt injection exfil triggers quarantine", async () => {
		const dir = tempDir();
		dirs.push(dir);

		const scenario = SCENARIOS.find((s) => s.id === "pi_secret_exfiltration")!;
		const result = await scenario.run(join(dir, "pi_exfil.db"));
		expect(result.verdict).toBe("BLOCKED");
		expect(result.wasQuarantined).toBe(true);
		expect(result.enforcementMechanism).toBe("behavioral");
	});

	it("filesystem traversal blocked by capability", async () => {
		const dir = tempDir();
		dirs.push(dir);

		const scenario = SCENARIOS.find((s) => s.id === "fs_path_escape")!;
		const result = await scenario.run(join(dir, "fs_escape.db"));
		expect(result.verdict).toBe("BLOCKED");
		expect(result.enforcementMechanism).toBe("capability");
	});

	it("taint chain web→shell blocked by taint policy", async () => {
		const dir = tempDir();
		dirs.push(dir);

		const scenario = SCENARIOS.find((s) => s.id === "tc_web_to_shell")!;
		const result = await scenario.run(join(dir, "tc_web.db"));
		expect(result.verdict).toBe("BLOCKED");
		expect(result.enforcementMechanism).toBe("taint");
	});

	it("repeated probe triggers quarantine", async () => {
		const dir = tempDir();
		dirs.push(dir);

		const scenario = SCENARIOS.find((s) => s.id === "repeated_probe_quarantine")!;
		const result = await scenario.run(join(dir, "repeated.db"));
		expect(result.verdict).toBe("BLOCKED");
		expect(result.wasQuarantined).toBe(true);
		expect(result.enforcementMechanism).toBe("quarantine");
	});
});
