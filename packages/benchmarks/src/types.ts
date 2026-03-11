/**
 * Types for the AriKernel reproducible attack benchmark suite.
 */

export type AttackCategory =
	| "prompt_injection"
	| "tool_escalation"
	| "data_exfiltration"
	| "filesystem_traversal"
	| "database_escalation"
	| "taint_chain"
	| "cross_run_exfiltration"
	| "shared_store_contamination"
	| "egress_convergence"
	| "path_ambiguity_bypass"
	| "low_entropy_exfiltration";

export type EnforcementMechanism = "policy" | "capability" | "taint" | "behavioral" | "quarantine";

export interface BenchmarkResult {
	scenarioId: string;
	scenarioName: string;
	attackCategory: AttackCategory;
	description: string;
	verdict: "BLOCKED" | "ALLOWED" | "PARTIAL";
	enforcementMechanism: EnforcementMechanism | null;
	wasQuarantined: boolean;
	deniedCount: number;
	allowedCount: number;
	runId: string;
	auditDbPath: string;
	durationMs: number;
}

export interface BenchmarkSummary {
	totalScenarios: number;
	attacksBlocked: number;
	attacksBlockedPct: number;
	attacksPartial: number;
	attacksPartialPct: number;
	attacksAllowed: number;
	quarantinedRuns: number;
	quarantinedRunsPct: number;
	byCategory: Record<string, { blocked: number; partial: number; total: number }>;
	byMechanism: Record<string, number>;
}

export interface BenchmarkEnvironment {
	ariKernelVersion: string;
	gitSha: string;
	nodeVersion: string;
	platform: string;
}

export interface BenchmarkReport {
	generatedAt: string;
	environment: BenchmarkEnvironment;
	scenarios: BenchmarkResult[];
	summary: BenchmarkSummary;
}

export interface ScenarioDef {
	id: string;
	name: string;
	category: AttackCategory;
	description: string;
	run(dbPath: string): Promise<BenchmarkResult>;
}
