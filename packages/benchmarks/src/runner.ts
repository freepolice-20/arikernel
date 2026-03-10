import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { aggregateMetrics } from "./metrics.js";
import { SCENARIOS } from "./scenarios/index.js";
import type { BenchmarkResult, ScenarioDef } from "./types.js";

export async function runScenario(
	scenario: ScenarioDef,
	resultsDir: string,
): Promise<BenchmarkResult> {
	const dbPath = join(resultsDir, `${scenario.id}.db`);
	return scenario.run(dbPath);
}

export async function runAllScenarios(
	resultsDir: string,
	onProgress?: (result: BenchmarkResult, index: number, total: number) => void,
): Promise<BenchmarkResult[]> {
	mkdirSync(resultsDir, { recursive: true });

	const results: BenchmarkResult[] = [];

	for (let i = 0; i < SCENARIOS.length; i++) {
		const scenario = SCENARIOS[i];
		const result = await runScenario(scenario, resultsDir);
		results.push(result);
		onProgress?.(result, i, SCENARIOS.length);
	}

	return results;
}

export async function benchmark(
	resultsDir: string,
	onProgress?: (result: BenchmarkResult, index: number, total: number) => void,
) {
	const results = await runAllScenarios(resultsDir, onProgress);
	const summary = aggregateMetrics(results);
	return { results, summary };
}

export { SCENARIOS };
