import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
	benchmark,
	buildReport,
	defaultResultsPaths,
	printSecurityReport,
	writeJsonReport,
	writeJsonlReport,
	writeMarkdownReport,
} from "@arikernel/benchmarks";
import type { BenchmarkResult } from "@arikernel/benchmarks";

export async function runBenchmarkSecurity(resultsDir?: string): Promise<void> {
	const __dirname = dirname(fileURLToPath(import.meta.url));
	const repoRoot = resolve(__dirname, "..", "..", "..", "..");
	const dir = resultsDir ?? resolve(repoRoot, "benchmarks", "results");

	console.log("\n  Running AriKernel Security Benchmark...\n");

	const { results, summary } = await benchmark(
		dir,
		(result: BenchmarkResult, index: number, total: number) => {
			const icon =
				result.verdict === "BLOCKED"
					? "BLOCKED"
					: result.verdict === "PARTIAL"
						? "PARTIAL"
						: "ALLOWED";
			console.log(
				`  [${index + 1}/${total}] ${icon}  ${result.scenarioId} (${result.durationMs}ms)`,
			);
		},
	);

	const report = buildReport(results, summary);
	printSecurityReport(report);

	const paths = defaultResultsPaths(repoRoot);
	writeJsonReport(report, paths.json);
	writeJsonlReport(report, paths.jsonl);
	writeMarkdownReport(report, paths.markdown);

	console.log("  Reports written to:");
	console.log(`    ${paths.json}`);
	console.log(`    ${paths.jsonl}`);
	console.log(`    ${paths.markdown}\n`);

	// Exit with non-zero if any attack was not blocked
	if (summary.attacksAllowed > 0) {
		process.exitCode = 1;
	}
}
