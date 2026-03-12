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
	it("exports 18 scenarios", () => {
		expect(SCENARIOS).toHaveLength(18);
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
		expect(categories).toContain("cross_run_exfiltration");
		expect(categories).toContain("shared_store_contamination");
		expect(categories).toContain("egress_convergence");
		expect(categories).toContain("path_ambiguity_bypass");
		expect(categories).toContain("low_entropy_exfiltration");
	});
});

describe("benchmark — all attacks blocked", () => {
	it("blocks or mitigates all 18 attack scenarios", async () => {
		const dir = tempDir();
		dirs.push(dir);

		const { results, summary } = await benchmark(dir);

		expect(results).toHaveLength(18);

		for (const r of results) {
			expect(["BLOCKED", "PARTIAL"]).toContain(r.verdict);
			expect(r.enforcementMechanism).toBeTruthy();
			expect(r.runId).toBeTruthy();
			expect(r.durationMs).toBeGreaterThanOrEqual(0);
		}

		// No attacks should be fully allowed
		expect(summary.attacksAllowed).toBe(0);
		expect(summary.attacksBlocked + summary.attacksPartial).toBe(18);
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
			// Every category should have all attacks either blocked or partially mitigated
			expect(counts.blocked + counts.partial).toBe(counts.total);
		}
	});
});

describe("individual scenarios", () => {
	it("prompt injection exfil triggers quarantine", async () => {
		const dir = tempDir();
		dirs.push(dir);

		// biome-ignore lint/style/noNonNullAssertion: scenario ID is a known constant
		const scenario = SCENARIOS.find((s) => s.id === "pi_secret_exfiltration")!;
		const result = await scenario.run(join(dir, "pi_exfil.db"));
		expect(result.verdict).toBe("BLOCKED");
		expect(result.wasQuarantined).toBe(true);
		expect(result.enforcementMechanism).toBe("behavioral");
	});

	it("filesystem traversal blocked by capability", async () => {
		const dir = tempDir();
		dirs.push(dir);

		// biome-ignore lint/style/noNonNullAssertion: scenario ID is a known constant
		const scenario = SCENARIOS.find((s) => s.id === "fs_path_escape")!;
		const result = await scenario.run(join(dir, "fs_escape.db"));
		expect(result.verdict).toBe("BLOCKED");
		expect(result.enforcementMechanism).toBe("capability");
	});

	it("taint chain web→shell blocked by taint policy", async () => {
		const dir = tempDir();
		dirs.push(dir);

		// biome-ignore lint/style/noNonNullAssertion: scenario ID is a known constant
		const scenario = SCENARIOS.find((s) => s.id === "tc_web_to_shell")!;
		const result = await scenario.run(join(dir, "tc_web.db"));
		expect(result.verdict).toBe("BLOCKED");
		expect(result.enforcementMechanism).toBe("taint");
	});

	it("repeated probe triggers quarantine", async () => {
		const dir = tempDir();
		dirs.push(dir);

		// biome-ignore lint/style/noNonNullAssertion: scenario ID is a known constant
		const scenario = SCENARIOS.find((s) => s.id === "repeated_probe_quarantine")!;
		const result = await scenario.run(join(dir, "repeated.db"));
		expect(result.verdict).toBe("BLOCKED");
		expect(result.wasQuarantined).toBe(true);
		expect(result.enforcementMechanism).toBe("quarantine");
	});

	it("cross-run credential exfil blocked by behavioral rules", async () => {
		const dir = tempDir();
		dirs.push(dir);

		// biome-ignore lint/style/noNonNullAssertion: scenario ID is a known constant
		const scenario = SCENARIOS.find((s) => s.id === "cross_run_credential_exfil")!;
		const result = await scenario.run(join(dir, "cross_run.db"));
		expect(result.verdict).toBe("BLOCKED");
		expect(result.wasQuarantined).toBe(true);
		expect(result.enforcementMechanism).toBe("behavioral");
	});

	it("shared store contamination blocked by taint policy", async () => {
		const dir = tempDir();
		dirs.push(dir);

		// biome-ignore lint/style/noNonNullAssertion: scenario ID is a known constant
		const scenario = SCENARIOS.find((s) => s.id === "shared_store_contamination")!;
		const result = await scenario.run(join(dir, "shared_store.db"));
		expect(result.verdict).toBe("BLOCKED");
		expect(result.enforcementMechanism).toBe("taint");
	});

	it("egress convergence detected and blocked", async () => {
		const dir = tempDir();
		dirs.push(dir);

		// biome-ignore lint/style/noNonNullAssertion: scenario ID is a known constant
		const scenario = SCENARIOS.find((s) => s.id === "egress_convergence_cp3")!;
		const result = await scenario.run(join(dir, "egress.db"));
		expect(result.verdict).toBe("BLOCKED");
		expect(result.wasQuarantined).toBe(true);
		expect(result.enforcementMechanism).toBe("behavioral");
	});

	it("path ambiguity bypass blocked by capability constraints", async () => {
		const dir = tempDir();
		dirs.push(dir);

		// biome-ignore lint/style/noNonNullAssertion: scenario ID is a known constant
		const scenario = SCENARIOS.find((s) => s.id === "path_ambiguity_bypass")!;
		const result = await scenario.run(join(dir, "path_ambig.db"));
		expect(result.verdict).toBe("BLOCKED");
		expect(result.enforcementMechanism).toBe("capability");
	});

	it("low-entropy exfil at least partially mitigated", async () => {
		const dir = tempDir();
		dirs.push(dir);

		// biome-ignore lint/style/noNonNullAssertion: scenario ID is a known constant
		const scenario = SCENARIOS.find((s) => s.id === "low_entropy_exfil")!;
		const result = await scenario.run(join(dir, "low_entropy.db"));
		expect(["BLOCKED", "PARTIAL"]).toContain(result.verdict);
		expect(result.wasQuarantined).toBe(true);
		expect(result.enforcementMechanism).toBe("behavioral");
	});
});
