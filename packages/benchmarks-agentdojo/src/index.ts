/**
 * AgentDojo-aligned benchmark harness entry point.
 *
 * Usage:
 *   npx tsx packages/benchmarks-agentdojo/src/index.ts
 *
 * Or via root script:
 *   npx pnpm benchmark:agentdojo
 */

import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
	buildReport,
	defaultResultsPaths,
	printConsoleSummary,
	writeJsonReport,
	writeJsonlReport,
	writeMarkdownReport,
} from "./results.js";
import { benchmark } from "./runner.js";
import type { ScenarioResult } from "./types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
// Repo root: packages/benchmarks-agentdojo/src → ../../..
const REPO_ROOT = resolve(__dirname, "..", "..", "..");
const RESULTS_DIR = resolve(REPO_ROOT, "benchmarks", "results");

function progressCallback(result: ScenarioResult, index: number, total: number): void {
	const blocked =
		result.exfiltrationPrevented === true ||
		result.sensitiveReadPrevented === true ||
		result.wasQuarantined;
	const icon = blocked ? "✓" : "✗";
	console.log(`  [${index + 1}/${total}] ${icon} ${result.scenarioId} (${result.durationMs}ms)`);
}

console.log("\nRunning AriKernel AgentDojo benchmark...\n");

const { results, summary } = await benchmark(RESULTS_DIR, progressCallback);

const report = buildReport(results, summary);
const paths = defaultResultsPaths(REPO_ROOT);

const agentDojoResultsPath = resolve(REPO_ROOT, "benchmarks", "agentdojo-results.md");

printConsoleSummary(report);
writeJsonReport(report, paths.json);
writeJsonlReport(report, paths.jsonl);
writeMarkdownReport(report, paths.markdown);
writeMarkdownReport(report, agentDojoResultsPath);

console.log(`  AgentDojo report: benchmarks/agentdojo-results.md\n`);
