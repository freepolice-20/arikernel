import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { type ToolCallRequest, deriveCapabilityClass as coreDerive } from "@arikernel/core";
import { parse as parseYaml } from "yaml";
import {
	ACTION_MAP,
	type ScenarioStepInput,
	type YamlScenarioInput,
	yamlScenarioSchema,
	yamlScenarioSuiteSchema,
} from "./scenario-schema.js";
import type { AttackScenario, AttackStep } from "./simulate.js";

// ── Step conversion ──────────────────────────────────────────────────

function resolveAction(action: string): { toolClass: string; action: string } {
	if (action in ACTION_MAP) return ACTION_MAP[action];
	// Support raw toolClass.action format (e.g. "http.get")
	const dot = action.indexOf(".");
	if (dot > 0) {
		return { toolClass: action.slice(0, dot), action: action.slice(dot + 1) };
	}
	throw new Error(`Unknown action: ${action}`);
}

function buildParameters(step: ScenarioStepInput): Record<string, unknown> {
	const params: Record<string, unknown> = {};
	if (step.url) params.url = step.url;
	if (step.path) params.path = step.path;
	if (step.command) params.command = step.command;
	if (step.query) params.query = step.query;
	if (step.body !== undefined) params.body = step.body;
	if (step.headers) params.headers = step.headers;
	return params;
}


function convertStep(step: ScenarioStepInput, index: number): AttackStep {
	const resolved = resolveAction(step.action);
	const taintLabels = (step.taintSources ?? []).map((source) => ({
		source: source as "web" | "rag" | "email",
		origin: "scenario",
		confidence: 1.0,
		addedAt: new Date().toISOString(),
	}));

	const request: ToolCallRequest = {
		toolClass: resolved.toolClass as ToolCallRequest["toolClass"],
		action: resolved.action,
		parameters: buildParameters(step),
		...(taintLabels.length > 0 ? { taintLabels } : {}),
	};

	// Auto-derive capabilityClass using the core inverse map
	const capabilityClass =
		step.capabilityClass ?? coreDerive(resolved.toolClass, resolved.action);

	return {
		label: step.label ?? `Step ${index + 1}: ${step.action}`,
		request,
		capabilityClass: capabilityClass as never,
	};
}

// ── Scenario conversion ──────────────────────────────────────────────

function convertScenario(input: YamlScenarioInput): AttackScenario {
	return {
		name: input.scenario,
		description: input.description ?? "",
		attackPrompt: `Scenario: ${input.scenario}`,
		expectedAgentBehavior: "Execute all steps",
		expectedKernelResponse: input.expectedBlocked
			? "Block at least one step"
			: "Allow all steps",
		steps: input.steps.map(convertStep),
		expectedBlocked: input.expectedBlocked,
		expectedQuarantined: input.expectedQuarantined,
	};
}

// ── Public API ────────────────────────────────────────────────────────

/**
 * Load attack scenarios from a YAML file.
 * Supports both single-scenario and multi-scenario (suite) formats.
 */
export function loadScenarioFile(filePath: string): AttackScenario[] {
	const abs = resolve(filePath);
	const content = readFileSync(abs, "utf-8");
	const raw = parseYaml(content);

	// Try single scenario first
	const single = yamlScenarioSchema.safeParse(raw);
	if (single.success) {
		return [convertScenario(single.data)];
	}

	// Try suite format
	const suite = yamlScenarioSuiteSchema.safeParse(raw);
	if (suite.success) {
		return suite.data.scenarios.map(convertScenario);
	}

	// If raw is an array, try parsing each element as a scenario
	if (Array.isArray(raw)) {
		const scenarios: AttackScenario[] = [];
		for (const item of raw) {
			const parsed = yamlScenarioSchema.safeParse(item);
			if (!parsed.success) {
				throw new Error(
					`Invalid scenario in ${filePath}: ${parsed.error.errors.map((e) => e.message).join(", ")}`,
				);
			}
			scenarios.push(convertScenario(parsed.data));
		}
		return scenarios;
	}

	throw new Error(
		`Invalid scenario file ${filePath}: ${single.error.errors.map((e) => e.message).join(", ")}`,
	);
}

/**
 * Load all YAML scenario files from a directory.
 */
export function loadScenarioDirectory(dirPath: string): AttackScenario[] {
	const abs = resolve(dirPath);
	const entries = readdirSync(abs);
	const scenarios: AttackScenario[] = [];

	for (const entry of entries) {
		if (!entry.endsWith(".yaml") && !entry.endsWith(".yml")) continue;
		const full = join(abs, entry);
		if (!statSync(full).isFile()) continue;
		scenarios.push(...loadScenarioFile(full));
	}

	if (scenarios.length === 0) {
		throw new Error(`No scenario files found in ${abs}`);
	}

	return scenarios;
}
