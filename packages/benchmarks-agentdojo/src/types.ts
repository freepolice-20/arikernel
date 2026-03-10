/**
 * Types for the AgentDojo-aligned benchmark harness.
 */

/**
 * Result of executing a single attack scenario through the AriKernel pipeline.
 */
export interface ScenarioResult {
	/** Unique identifier for the scenario. */
	scenarioId: string;
	/** Human-readable scenario name. */
	scenarioName: string;
	/** AgentDojo-aligned attack class (e.g. "prompt_injection", "privilege_escalation"). */
	attackClass: string;
	/** Which enforcement mechanism blocked the attack (or null if attack succeeded). */
	blockedBy: "behavioral_rule" | "taint_policy" | "capability_denial" | "quarantine" | null;
	/** Whether the run entered restricted mode (behavioral quarantine). */
	wasQuarantined: boolean;
	/**
	 * Whether the pipeline denied the sensitive-data-access step.
	 * null = scenario does not include a sensitive read step.
	 */
	sensitiveReadPrevented: boolean | null;
	/**
	 * Whether the pipeline denied the exfiltration step.
	 * null = scenario does not include an exfiltration step.
	 */
	exfiltrationPrevented: boolean | null;
	/** Number of tool calls/capabilities denied during the scenario. */
	deniedCount: number;
	/** Number of tool calls allowed (reached execution) during the scenario. */
	allowedCount: number;
	/** The AriKernel run ID — use with audit log replay. */
	runId: string;
	/** Path to the SQLite audit database for this run. */
	auditDbPath: string;
	/** Wall-clock time to run the scenario (ms). */
	durationMs: number;
	/** Short explanation of the outcome. */
	outcomeNote: string;
}

/**
 * Aggregate metrics computed from all scenario results.
 */
export interface BenchmarkSummary {
	totalScenarios: number;
	/** Scenarios where the attack goal was blocked. */
	attacksBlocked: number;
	attacksBlockedPct: number;
	/** Runs that entered behavioral quarantine. */
	quarantinedRuns: number;
	quarantinedRunsPct: number;
	/** Of scenarios with a sensitive-read step, % where read was denied by pipeline. */
	sensitiveReadsPreventedPct: number;
	/** Of scenarios with an exfiltration step, % where exfiltration was denied. */
	exfiltrationPreventedPct: number;
}

/**
 * Reproducibility metadata captured at benchmark execution time.
 */
export interface BenchmarkEnvironment {
	/** AriKernel package version. */
	ariKernelVersion: string;
	/** Git commit SHA (short). */
	gitSha: string;
	/** Node.js version. */
	nodeVersion: string;
	/** OS platform (e.g., 'linux', 'darwin', 'win32'). */
	platform: string;
}

/**
 * Full benchmark report written to disk and console.
 */
export interface BenchmarkReport {
	generatedAt: string;
	environment: BenchmarkEnvironment;
	scenarios: ScenarioResult[];
	summary: BenchmarkSummary;
}
