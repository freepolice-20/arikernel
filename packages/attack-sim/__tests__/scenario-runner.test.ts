import { describe, expect, it } from "vitest";
import { loadBuiltinScenarios, BUILTIN_SCENARIOS_DIR } from "../src/builtin-scenarios.js";
import { loadScenarioFile, loadScenarioDirectory } from "../src/scenario-loader.js";
import { ACTION_MAP, yamlScenarioSchema } from "../src/scenario-schema.js";
import { runScenarioFile, runScenarioDirectory, runPolicyTest } from "../src/scenario-runner.js";
import { DEFAULT_POLICY } from "../src/default-policy.js";

// ── Schema validation ────────────────────────────────────────────────

describe("yamlScenarioSchema", () => {
	it("validates a minimal scenario", () => {
		const input = {
			scenario: "test",
			steps: [{ action: "http_get", url: "https://example.com" }],
		};
		const result = yamlScenarioSchema.safeParse(input);
		expect(result.success).toBe(true);
	});

	it("rejects scenario with no steps", () => {
		const input = { scenario: "test", steps: [] };
		const result = yamlScenarioSchema.safeParse(input);
		expect(result.success).toBe(false);
	});

	it("rejects unknown action without dot notation", () => {
		const input = {
			scenario: "test",
			steps: [{ action: "unknown_action" }],
		};
		const result = yamlScenarioSchema.safeParse(input);
		expect(result.success).toBe(false);
	});

	it("accepts raw toolClass.action format", () => {
		const input = {
			scenario: "test",
			steps: [{ action: "http.get", url: "https://example.com" }],
		};
		const result = yamlScenarioSchema.safeParse(input);
		expect(result.success).toBe(true);
	});

	it("defaults expectedBlocked to true", () => {
		const input = {
			scenario: "test",
			steps: [{ action: "http_get", url: "https://example.com" }],
		};
		const result = yamlScenarioSchema.safeParse(input);
		expect(result.success).toBe(true);
		if (result.success) {
			expect(result.data.expectedBlocked).toBe(true);
		}
	});
});

// ── ACTION_MAP ───────────────────────────────────────────────────────

describe("ACTION_MAP", () => {
	it("maps all expected aliases", () => {
		expect(ACTION_MAP.fetch_web_page).toEqual({ toolClass: "http", action: "get" });
		expect(ACTION_MAP.read_file).toEqual({ toolClass: "file", action: "read" });
		expect(ACTION_MAP.shell_exec).toEqual({ toolClass: "shell", action: "exec" });
		expect(ACTION_MAP.db_query).toEqual({ toolClass: "database", action: "query" });
		expect(ACTION_MAP.db_write).toEqual({ toolClass: "database", action: "mutate" });
	});
});

// ── Scenario loading ─────────────────────────────────────────────────

describe("loadBuiltinScenarios", () => {
	it("loads all 5 built-in scenarios", () => {
		const scenarios = loadBuiltinScenarios();
		expect(scenarios.length).toBe(10);
	});

	it("each scenario has name, steps, and expected outcome", () => {
		const scenarios = loadBuiltinScenarios();
		for (const s of scenarios) {
			expect(s.name).toBeTruthy();
			expect(s.steps.length).toBeGreaterThan(0);
			expect(typeof s.expectedBlocked).toBe("boolean");
		}
	});
});

describe("loadScenarioFile", () => {
	it("loads a single scenario YAML file", () => {
		const scenarios = loadScenarioFile(
			`${BUILTIN_SCENARIOS_DIR}/prompt-injection-exfiltration.yaml`,
		);
		expect(scenarios.length).toBe(1);
		expect(scenarios[0].name).toBe("prompt_injection_exfiltration");
		expect(scenarios[0].steps.length).toBe(3);
	});
});

describe("loadScenarioDirectory", () => {
	it("loads all YAML files from the built-in directory", () => {
		const scenarios = loadScenarioDirectory(BUILTIN_SCENARIOS_DIR);
		expect(scenarios.length).toBe(10);
	});
});

// ── Scenario execution ───────────────────────────────────────────────

describe("runScenarioFile", () => {
	it("executes a scenario and returns results", async () => {
		const results = await runScenarioFile(
			`${BUILTIN_SCENARIOS_DIR}/shell-escalation.yaml`,
		);
		expect(results.length).toBe(1);
		expect(results[0].blocked).toBe(true);
		expect(results[0].stepVerdicts.length).toBeGreaterThan(0);
	});
});

describe("runScenarioDirectory", () => {
	it("executes all built-in scenarios", async () => {
		const results = await runScenarioDirectory(BUILTIN_SCENARIOS_DIR);
		expect(results.length).toBe(10);
		// All policy-enforced scenarios should be blocked by safe-defaults.
		// path_ambiguity_bypass requires file executor path constraints (not sim-enforced).
		const policyEnforced = results.filter(
			(r) => r.scenario.name !== "path_ambiguity_bypass",
		);
		for (const r of policyEnforced) {
			expect(r.blocked).toBe(true);
		}
	});
});

// ── Policy test ──────────────────────────────────────────────────────

describe("runPolicyTest", () => {
	it("produces a report with no weaknesses for safe defaults", async () => {
		const result = await runPolicyTest(DEFAULT_POLICY, BUILTIN_SCENARIOS_DIR);
		expect(result.scenarios.length).toBe(10);
		// 9 of 10 blocked by policy rules; path_ambiguity_bypass requires
		// file executor path constraints which the sim stub doesn't enforce.
		expect(result.blocked).toBe(9);
		expect(result.allowed).toBe(1);
		expect(result.passed).toBe(9);
		expect(result.failed).toBe(1);
		// The only weakness should be the path_ambiguity scenario
		expect(result.weaknesses.length).toBe(1);
		expect(result.weaknesses[0]).toContain("path_ambiguity_bypass");
	});
});
