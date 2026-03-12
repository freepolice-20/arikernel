import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runScenario } from "../src/runner.js";
import { SCENARIOS } from "../src/scenarios/index.js";

function tempDir(): string {
	return mkdtempSync(join(tmpdir(), "arikernel-bench-test-"));
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
	it("exports exactly 9 scenarios", () => {
		expect(SCENARIOS).toHaveLength(9);
	});

	it("each scenario has unique id, name, attackClass, and run function", () => {
		const ids = SCENARIOS.map((s) => s.id);
		const unique = new Set(ids);
		expect(unique.size).toBe(SCENARIOS.length);
		for (const s of SCENARIOS) {
			expect(s.name).toBeTruthy();
			expect(s.attackClass).toBeTruthy();
			expect(typeof s.run).toBe("function");
		}
	});
});

describe("runScenario — determinism", () => {
	it("scenario 2 (taint policy) always blocks exfiltration", async () => {
		const dir = tempDir();
		dirs.push(dir);
		// biome-ignore lint/style/noNonNullAssertion: scenario ID is a known constant
		const scenario = SCENARIOS.find((s) => s.id === "prompt_injection_exfiltration")!;
		const result = await runScenario(scenario, dir);
		expect(result.exfiltrationPrevented).toBe(true);
		expect(result.blockedBy).toBe("taint_policy");
	});

	it("scenario 3 (escalation) triggers quarantine", async () => {
		const dir = tempDir();
		dirs.push(dir);
		// biome-ignore lint/style/noNonNullAssertion: scenario ID is a known constant
		const scenario = SCENARIOS.find((s) => s.id === "escalation_after_denial")!;
		const result = await runScenario(scenario, dir);
		expect(result.wasQuarantined).toBe(true);
	});

	it("scenario 5 (repeated probe) blocks all sensitive reads and quarantines", async () => {
		const dir = tempDir();
		dirs.push(dir);
		// biome-ignore lint/style/noNonNullAssertion: scenario ID is a known constant
		const scenario = SCENARIOS.find((s) => s.id === "repeated_sensitive_probe")!;
		const result = await runScenario(scenario, dir);
		expect(result.sensitiveReadPrevented).toBe(true);
		expect(result.wasQuarantined).toBe(true);
		expect(result.deniedCount).toBe(5);
	});

	it("result has required fields and a valid runId", async () => {
		const dir = tempDir();
		dirs.push(dir);
		const result = await runScenario(SCENARIOS[0], dir);
		expect(result.scenarioId).toBeTruthy();
		expect(result.scenarioName).toBeTruthy();
		expect(result.runId).toBeTruthy();
		expect(typeof result.durationMs).toBe("number");
		expect(result.durationMs).toBeGreaterThanOrEqual(0);
		expect(result.auditDbPath).toContain(result.scenarioId);
	});

	it("scenario 1 (prompt injection → shell) quarantines and blocks shell", async () => {
		const dir = tempDir();
		dirs.push(dir);
		// biome-ignore lint/style/noNonNullAssertion: scenario ID is a known constant
		const scenario = SCENARIOS.find((s) => s.id === "prompt_injection_sensitive_file")!;

		// Stub fetch for the HTTP executor
		const orig = globalThis.fetch;
		globalThis.fetch = async () =>
			({
				ok: true,
				status: 200,
				headers: { get: () => "text/plain", entries: () => [] },
				text: async () => "injected content",
			}) as unknown as Response;

		try {
			const result = await runScenario(scenario, dir);
			expect(result.wasQuarantined).toBe(true);
			expect(result.exfiltrationPrevented).toBe(true);
		} finally {
			globalThis.fetch = orig;
		}
	});

	it("scenario 4 (web taint → file write) blocks tainted write", async () => {
		const dir = tempDir();
		dirs.push(dir);
		// biome-ignore lint/style/noNonNullAssertion: scenario ID is a known constant
		const scenario = SCENARIOS.find((s) => s.id === "web_taint_sensitive_probe")!;
		const result = await runScenario(scenario, dir);
		expect(result.exfiltrationPrevented).toBe(true);
		expect(result.blockedBy).toBe("taint_policy");
	});
});
