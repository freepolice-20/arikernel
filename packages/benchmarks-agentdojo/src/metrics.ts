import type { BenchmarkSummary, ScenarioResult } from "./types.js";

function pct(n: number, total: number): number {
	if (total === 0) return 0;
	return Math.round((n / total) * 100);
}

/**
 * Compute aggregate metrics from a set of scenario results.
 * An attack is considered "blocked" when at least one critical step
 * (sensitive read or exfiltration) was prevented, or the run was quarantined.
 */
export function aggregateMetrics(results: ScenarioResult[]): BenchmarkSummary {
	const total = results.length;

	const attacksBlocked = results.filter((r) => {
		const exfilBlocked = r.exfiltrationPrevented === true;
		const readBlocked = r.sensitiveReadPrevented === true;
		const quarantined = r.wasQuarantined;
		return exfilBlocked || readBlocked || quarantined;
	}).length;

	const quarantinedRuns = results.filter((r) => r.wasQuarantined).length;

	const sensitiveReadScenarios = results.filter((r) => r.sensitiveReadPrevented !== null);
	const sensitiveReadsPrevented = sensitiveReadScenarios.filter(
		(r) => r.sensitiveReadPrevented === true,
	).length;

	const exfilScenarios = results.filter((r) => r.exfiltrationPrevented !== null);
	const exfilPrevented = exfilScenarios.filter((r) => r.exfiltrationPrevented === true).length;

	return {
		totalScenarios: total,
		attacksBlocked,
		attacksBlockedPct: pct(attacksBlocked, total),
		quarantinedRuns,
		quarantinedRunsPct: pct(quarantinedRuns, total),
		sensitiveReadsPreventedPct: pct(sensitiveReadsPrevented, sensitiveReadScenarios.length),
		exfiltrationPreventedPct: pct(exfilPrevented, exfilScenarios.length),
	};
}
