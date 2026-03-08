import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import type { BenchmarkReport, BenchmarkSummary, ScenarioResult } from './types.js';

const PASS = '✓';
const FAIL = '✗';

function blocked(r: ScenarioResult): boolean {
	return r.exfiltrationPrevented === true || r.sensitiveReadPrevented === true || r.wasQuarantined;
}

/**
 * Print a human-readable benchmark summary to stdout.
 */
export function printConsoleSummary(report: BenchmarkReport): void {
	const s = report.summary;
	console.log('\n╔══════════════════════════════════════════════╗');
	console.log('║      AriKernel — AgentDojo Benchmark         ║');
	console.log('╚══════════════════════════════════════════════╝\n');

	for (const r of report.scenarios) {
		const ok = blocked(r);
		const icon = ok ? PASS : FAIL;
		const blockedByStr = r.blockedBy ? ` (${r.blockedBy})` : '';
		console.log(`  ${icon} ${r.scenarioName}${blockedByStr}`);
		console.log(`     ${r.outcomeNote}`);
	}

	console.log('\n──────────────────────────────────────────────');
	console.log(`  Scenarios run:          ${s.totalScenarios}`);
	console.log(`  Attacks blocked:        ${s.attacksBlocked}/${s.totalScenarios} (${s.attacksBlockedPct}%)`);
	console.log(`  Runs quarantined:       ${s.quarantinedRuns}/${s.totalScenarios} (${s.quarantinedRunsPct}%)`);
	console.log(`  Sensitive reads blocked: ${s.sensitiveReadsPreventedPct}%`);
	console.log(`  Exfiltration blocked:   ${s.exfiltrationPreventedPct}%`);
	console.log('──────────────────────────────────────────────\n');
	console.log(`  Audit logs: benchmarks/results/<scenario-id>.db`);
	console.log(`  JSON report: benchmarks/results/latest.json`);
	console.log(`  Markdown report: benchmarks/results/latest.md\n`);
}

/**
 * Write a machine-readable JSON report to disk.
 */
export function writeJsonReport(report: BenchmarkReport, outPath: string): void {
	mkdirSync(dirname(outPath), { recursive: true });
	writeFileSync(outPath, JSON.stringify(report, null, 2), 'utf8');
}

/**
 * Write a Markdown report to disk.
 */
export function writeMarkdownReport(report: BenchmarkReport, outPath: string): void {
	mkdirSync(dirname(outPath), { recursive: true });
	const s = report.summary;
	const lines: string[] = [];

	lines.push('# AriKernel — AgentDojo Benchmark Results\n');
	lines.push(`Generated: ${report.generatedAt}\n`);
	lines.push('## Summary\n');
	lines.push(`| Metric | Value |`);
	lines.push(`|--------|-------|`);
	lines.push(`| Scenarios run | ${s.totalScenarios} |`);
	lines.push(`| Attacks blocked | ${s.attacksBlocked}/${s.totalScenarios} (${s.attacksBlockedPct}%) |`);
	lines.push(`| Runs quarantined | ${s.quarantinedRuns}/${s.totalScenarios} (${s.quarantinedRunsPct}%) |`);
	lines.push(`| Sensitive reads blocked | ${s.sensitiveReadsPreventedPct}% |`);
	lines.push(`| Exfiltration blocked | ${s.exfiltrationPreventedPct}% |`);
	lines.push('');
	lines.push('## Scenario Results\n');
	lines.push('| Scenario | Attack Class | Blocked By | Quarantined | Sensitive Read Prevented | Exfil Prevented |');
	lines.push('|----------|-------------|------------|-------------|--------------------------|-----------------|');

	for (const r of report.scenarios) {
		const b = blocked(r) ? 'Yes' : 'No';
		const q = r.wasQuarantined ? 'Yes' : 'No';
		const sr = r.sensitiveReadPrevented === null ? 'N/A' : r.sensitiveReadPrevented ? 'Yes' : 'No';
		const ef = r.exfiltrationPrevented === null ? 'N/A' : r.exfiltrationPrevented ? 'Yes' : 'No';
		const by = r.blockedBy ?? (b === 'Yes' ? 'yes' : 'no — attack succeeded');
		lines.push(`| ${r.scenarioName} | ${r.attackClass} | ${by} | ${q} | ${sr} | ${ef} |`);
	}

	lines.push('');
	lines.push('## Scenario Details\n');
	for (const r of report.scenarios) {
		lines.push(`### ${r.scenarioName}`);
		lines.push('');
		lines.push(`- **Attack class**: ${r.attackClass}`);
		lines.push(`- **Outcome**: ${r.outcomeNote}`);
		lines.push(`- **Blocked by**: ${r.blockedBy ?? 'not blocked'}`);
		lines.push(`- **Quarantined**: ${r.wasQuarantined}`);
		lines.push(`- **Denied calls**: ${r.deniedCount}`);
		lines.push(`- **Allowed calls**: ${r.allowedCount}`);
		lines.push(`- **Run ID**: \`${r.runId}\``);
		lines.push(`- **Audit DB**: \`${r.auditDbPath}\``);
		lines.push('');
		lines.push(`To replay: \`node apps/cli/dist/main.js replay --db ${r.auditDbPath}\``);
		lines.push('');
	}

	writeFileSync(outPath, lines.join('\n'), 'utf8');
}

/**
 * Build the full BenchmarkReport from scenario results.
 */
export function buildReport(
	results: ScenarioResult[],
	summary: BenchmarkSummary,
): BenchmarkReport {
	return {
		generatedAt: new Date().toISOString(),
		scenarios: results,
		summary,
	};
}

/**
 * Default paths for results artifacts relative to the repo root.
 */
export function defaultResultsPaths(repoRoot: string): {
	json: string;
	markdown: string;
} {
	return {
		json: join(repoRoot, 'benchmarks', 'results', 'latest.json'),
		markdown: join(repoRoot, 'benchmarks', 'results', 'latest.md'),
	};
}
