import type { BenchmarkResult, BenchmarkSummary } from "./types.js";

function pct(n: number, total: number): number {
	if (total === 0) return 0;
	return Math.round((n / total) * 100);
}

export function aggregateMetrics(results: BenchmarkResult[]): BenchmarkSummary {
	const total = results.length;
	const attacksBlocked = results.filter((r) => r.verdict === "BLOCKED").length;
	const attacksPartial = results.filter((r) => r.verdict === "PARTIAL").length;
	const attacksAllowed = results.filter((r) => r.verdict === "ALLOWED").length;
	const quarantinedRuns = results.filter((r) => r.wasQuarantined).length;

	const byCategory: Record<string, { blocked: number; partial: number; total: number }> = {};
	for (const r of results) {
		const cat = r.attackCategory;
		if (!byCategory[cat]) byCategory[cat] = { blocked: 0, partial: 0, total: 0 };
		byCategory[cat].total++;
		if (r.verdict === "BLOCKED") byCategory[cat].blocked++;
		if (r.verdict === "PARTIAL") byCategory[cat].partial++;
	}

	const byMechanism: Record<string, number> = {};
	for (const r of results) {
		if (r.enforcementMechanism) {
			byMechanism[r.enforcementMechanism] = (byMechanism[r.enforcementMechanism] ?? 0) + 1;
		}
	}

	return {
		totalScenarios: total,
		attacksBlocked,
		attacksBlockedPct: pct(attacksBlocked, total),
		attacksPartial,
		attacksPartialPct: pct(attacksPartial, total),
		attacksAllowed,
		quarantinedRuns,
		quarantinedRunsPct: pct(quarantinedRuns, total),
		byCategory,
		byMechanism,
	};
}
