import { join } from 'node:path';
import { mkdirSync } from 'node:fs';
import { SCENARIOS, type ScenarioDef } from './scenarios/index.js';
import { aggregateMetrics } from './metrics.js';
import type { ScenarioResult } from './types.js';

/**
 * Run a single scenario, writing its audit DB to resultsDir/<scenarioId>.db.
 */
export async function runScenario(
	scenario: ScenarioDef,
	resultsDir: string,
): Promise<ScenarioResult> {
	const dbPath = join(resultsDir, `${scenario.id}.db`);
	return scenario.run(dbPath);
}

/**
 * Run all benchmark scenarios sequentially (deterministic ordering).
 * Each scenario gets its own isolated AriKernel firewall instance and audit DB.
 *
 * @param resultsDir - Directory where audit DBs are written.
 * @param onProgress - Optional callback called after each scenario completes.
 */
export async function runAllScenarios(
	resultsDir: string,
	onProgress?: (result: ScenarioResult, index: number, total: number) => void,
): Promise<ScenarioResult[]> {
	mkdirSync(resultsDir, { recursive: true });

	const results: ScenarioResult[] = [];

	for (let i = 0; i < SCENARIOS.length; i++) {
		const scenario = SCENARIOS[i];
		const result = await runScenario(scenario, resultsDir);
		results.push(result);
		onProgress?.(result, i, SCENARIOS.length);
	}

	return results;
}

/**
 * Run all scenarios and compute the summary in one call.
 */
export async function benchmark(
	resultsDir: string,
	onProgress?: (result: ScenarioResult, index: number, total: number) => void,
) {
	const results = await runAllScenarios(resultsDir, onProgress);
	const summary = aggregateMetrics(results);
	return { results, summary };
}
