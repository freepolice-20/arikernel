import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
	benchmark,
	buildReport,
	defaultResultsPaths,
	printConsoleSummary,
	writeJsonReport,
	writeJsonlReport,
	writeMarkdownReport,
} from "@arikernel/benchmarks";
import type { BenchmarkResult } from "@arikernel/benchmarks";

export async function runBenchmark(resultsDir?: string): Promise<void> {
	const __dirname = dirname(fileURLToPath(import.meta.url));
	const repoRoot = resolve(__dirname, "..", "..", "..", "..");
	const dir = resultsDir ?? resolve(repoRoot, "benchmarks", "results");

	console.log("\n  Running AriKernel Attack Benchmark...\n");

	const { results, summary } = await benchmark(
		dir,
		(result: BenchmarkResult, index: number, total: number) => {
			const icon = result.verdict === "BLOCKED" ? "BLOCKED" : "ALLOWED";
			console.log(
				`  [${index + 1}/${total}] ${icon}  ${result.scenarioId} (${result.durationMs}ms)`,
			);
		},
	);

	const report = buildReport(results, summary);
	printConsoleSummary(report);

	const paths = defaultResultsPaths(repoRoot);
	writeJsonReport(report, paths.json);
	writeJsonlReport(report, paths.jsonl);
	writeMarkdownReport(report, paths.markdown);

	console.log("  Reports written to:");
	console.log(`    ${paths.json}`);
	console.log(`    ${paths.jsonl}`);
	console.log(`    ${paths.markdown}\n`);
}
