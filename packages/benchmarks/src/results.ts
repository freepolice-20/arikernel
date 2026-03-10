import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { VERSION } from "@arikernel/core";
import type {
	BenchmarkEnvironment,
	BenchmarkReport,
	BenchmarkResult,
	BenchmarkSummary,
} from "./types.js";

export function printConsoleSummary(report: BenchmarkReport): void {
	const s = report.summary;
	console.log("");
	console.log("  AriKernel Attack Benchmark");
	console.log("  ══════════════════════════════════════════════════════════════");
	console.log("");

	const maxName = Math.max(...report.scenarios.map((r) => r.scenarioName.length));

	for (const r of report.scenarios) {
		const icon = r.verdict === "BLOCKED" ? "BLOCKED" : "ALLOWED";
		const pad = " ".repeat(maxName - r.scenarioName.length + 2);
		const mech = r.enforcementMechanism ? ` (${r.enforcementMechanism})` : "";
		console.log(`  ${r.scenarioName}${pad}${icon}${mech}`);
	}

	console.log("");
	console.log("  ──────────────────────────────────────────────────────────────");
	console.log(`  Total attacks:   ${s.totalScenarios}`);
	console.log(`  Blocked:         ${s.attacksBlocked}`);
	console.log(`  Allowed:         ${s.totalScenarios - s.attacksBlocked}`);
	console.log(`  Block rate:      ${s.attacksBlockedPct}%`);
	console.log(`  Quarantined:     ${s.quarantinedRuns}`);
	console.log("");

	console.log("  By category:");
	for (const [cat, counts] of Object.entries(s.byCategory)) {
		console.log(`    ${cat}: ${counts.blocked}/${counts.total} blocked`);
	}
	console.log("");

	console.log("  By enforcement mechanism:");
	for (const [mech, count] of Object.entries(s.byMechanism)) {
		console.log(`    ${mech}: ${count}`);
	}
	console.log("  ──────────────────────────────────────────────────────────────\n");
}

export function writeJsonReport(report: BenchmarkReport, outPath: string): void {
	mkdirSync(dirname(outPath), { recursive: true });
	writeFileSync(outPath, JSON.stringify(report, null, 2), "utf8");
}

export function writeMarkdownReport(report: BenchmarkReport, outPath: string): void {
	mkdirSync(dirname(outPath), { recursive: true });
	const s = report.summary;
	const env = report.environment;
	const lines: string[] = [];

	lines.push("# AriKernel Attack Benchmark Results\n");
	lines.push(`Generated: ${report.generatedAt}\n`);

	lines.push("## Environment\n");
	lines.push("| Property | Value |");
	lines.push("|----------|-------|");
	lines.push(`| AriKernel version | ${env.ariKernelVersion} |`);
	lines.push(`| Git SHA | \`${env.gitSha}\` |`);
	lines.push(`| Node.js | ${env.nodeVersion} |`);
	lines.push(`| Platform | ${env.platform} |`);
	lines.push("");

	lines.push("## Summary\n");
	lines.push(`- **Total attacks**: ${s.totalScenarios}`);
	lines.push(`- **Blocked**: ${s.attacksBlocked}`);
	lines.push(`- **Block rate**: ${s.attacksBlockedPct}%`);
	lines.push(`- **Quarantined runs**: ${s.quarantinedRuns}`);
	lines.push("");

	lines.push("## Results\n");
	lines.push("| Attack | Category | Verdict | Enforcement | Quarantined |");
	lines.push("|--------|----------|---------|-------------|-------------|");

	for (const r of report.scenarios) {
		const q = r.wasQuarantined ? "Yes" : "No";
		const mech = r.enforcementMechanism ?? "-";
		lines.push(`| ${r.scenarioName} | ${r.attackCategory} | ${r.verdict} | ${mech} | ${q} |`);
	}

	lines.push("");
	lines.push("## Scenario Details\n");
	for (const r of report.scenarios) {
		lines.push(`### ${r.scenarioName}`);
		lines.push("");
		lines.push(`- **Category**: ${r.attackCategory}`);
		lines.push(`- **Description**: ${r.description}`);
		lines.push(`- **Verdict**: ${r.verdict}`);
		lines.push(`- **Enforcement**: ${r.enforcementMechanism ?? "none"}`);
		lines.push(`- **Denied calls**: ${r.deniedCount}`);
		lines.push(`- **Run ID**: \`${r.runId}\``);
		lines.push(`- **Audit DB**: \`${r.auditDbPath}\``);
		lines.push("");
	}

	writeFileSync(outPath, lines.join("\n"), "utf8");
}

export function writeJsonlReport(report: BenchmarkReport, outPath: string): void {
	mkdirSync(dirname(outPath), { recursive: true });
	const lines = report.scenarios.map((r) =>
		JSON.stringify({
			timestamp: report.generatedAt,
			gitSha: report.environment.gitSha,
			...r,
		}),
	);
	writeFileSync(outPath, `${lines.join("\n")}\n`, "utf8");
}

export function captureEnvironment(): BenchmarkEnvironment {
	let gitSha = "unknown";
	try {
		gitSha = execFileSync("git", ["rev-parse", "--short", "HEAD"], { encoding: "utf8" }).trim();
	} catch {
		/* not in a git repo */
	}

	return {
		ariKernelVersion: VERSION,
		gitSha,
		nodeVersion: process.version,
		platform: process.platform,
	};
}

export function buildReport(
	results: BenchmarkResult[],
	summary: BenchmarkSummary,
): BenchmarkReport {
	return {
		generatedAt: new Date().toISOString(),
		environment: captureEnvironment(),
		scenarios: results,
		summary,
	};
}

export function defaultResultsPaths(repoRoot: string) {
	return {
		json: join(repoRoot, "benchmarks", "results", "latest.json"),
		jsonl: join(repoRoot, "benchmarks", "results", "latest.jsonl"),
		markdown: join(repoRoot, "benchmarks", "results", "latest.md"),
	};
}
