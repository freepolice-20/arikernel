/**
 * Standalone benchmark runner.
 *
 * Usage:
 *   npx tsx packages/benchmarks/src/run.ts
 *   pnpm benchmark
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
import type { BenchmarkResult } from "./types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "..", "..", "..");
const RESULTS_DIR = resolve(REPO_ROOT, "benchmarks", "results");

function progressCallback(result: BenchmarkResult, index: number, total: number): void {
	const icon = result.verdict === "BLOCKED" ? "BLOCKED" : "ALLOWED";
	console.log(`  [${index + 1}/${total}] ${icon}  ${result.scenarioId} (${result.durationMs}ms)`);
}

console.log("\n  Running AriKernel Attack Benchmark...\n");

const { results, summary } = await benchmark(RESULTS_DIR, progressCallback);

const report = buildReport(results, summary);
const paths = defaultResultsPaths(REPO_ROOT);

printConsoleSummary(report);
writeJsonReport(report, paths.json);
writeJsonlReport(report, paths.jsonl);
writeMarkdownReport(report, paths.markdown);

console.log("  Reports written to:");
console.log(`    ${paths.json}`);
console.log(`    ${paths.jsonl}`);
console.log(`    ${paths.markdown}\n`);
