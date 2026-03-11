import type { AuditEvent, CapabilityClass, DecisionVerdict, PolicyRule } from "@arikernel/core";
import { ToolCallDeniedError } from "@arikernel/core";
import { type Firewall, createFirewall } from "@arikernel/runtime";
import { DEFAULT_POLICY } from "./default-policy.js";
import { loadScenarioDirectory, loadScenarioFile } from "./scenario-loader.js";
import type { AttackResult, AttackScenario, AttackStep, StepVerdict } from "./simulate.js";

// ── ANSI colors ──────────────────────────────────────────────────────

const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const CYAN = "\x1b[36m";
const MAGENTA = "\x1b[35m";
const RESET = "\x1b[0m";

// ── Timeline formatting ──────────────────────────────────────────────

export interface TimelineEntry {
	step: number;
	action: string;
	toolClass: string;
	verdict: string;
	reason: string;
	timestamp: string;
}

function buildTimeline(result: AttackResult): TimelineEntry[] {
	return result.stepVerdicts.map((sv, i) => ({
		step: i + 1,
		action: `${sv.step.request.toolClass}.${sv.step.request.action}`,
		toolClass: sv.step.request.toolClass,
		verdict: sv.verdict,
		reason: sv.reason,
		timestamp: new Date().toISOString(),
	}));
}

export function formatTimeline(result: AttackResult): string {
	const timeline = buildTimeline(result);
	const lines: string[] = [];

	lines.push(`\n${CYAN}${BOLD}Attack Timeline: ${result.scenario.name}${RESET}`);
	lines.push(`${DIM}${"─".repeat(60)}${RESET}`);

	for (const entry of timeline) {
		const verdictColor =
			entry.verdict === "allow"
				? GREEN
				: entry.verdict === "deny"
					? RED
					: entry.verdict === "capability-denied"
						? MAGENTA
						: YELLOW;
		const icon =
			entry.verdict === "allow" ? "✓" : entry.verdict === "deny" ? "✗" : "⊘";

		lines.push(
			`  ${DIM}${entry.step}.${RESET} ${verdictColor}${BOLD}${icon} ${entry.verdict.toUpperCase().padEnd(18)}${RESET} ${entry.action}`,
		);
		lines.push(`     ${DIM}${entry.reason}${RESET}`);
	}

	lines.push(`${DIM}${"─".repeat(60)}${RESET}`);

	if (result.blocked) {
		lines.push(
			`${RED}${BOLD}Attack blocked at step ${result.blockedAtStep}${RESET}`,
		);
		lines.push(`${DIM}Reason: ${result.blockReason}${RESET}`);
	} else {
		lines.push(
			`${GREEN}${BOLD}All steps allowed${RESET} ${RED}— attack was NOT stopped${RESET}`,
		);
	}

	if (result.quarantined) {
		lines.push(`${MAGENTA}${BOLD}Session quarantined${RESET}`);
	}

	lines.push("");
	return lines.join("\n");
}

// ── Policy test report ───────────────────────────────────────────────

export interface PolicyTestResult {
	policySource: string;
	scenarios: AttackResult[];
	blocked: number;
	allowed: number;
	passed: number;
	failed: number;
	weaknesses: string[];
}

function identifyWeaknesses(results: AttackResult[]): string[] {
	const weaknesses: string[] = [];

	const unblocked = results.filter((r) => r.scenario.expectedBlocked && !r.blocked);
	for (const r of unblocked) {
		weaknesses.push(
			`"${r.scenario.name}" was expected to be blocked but all steps were allowed`,
		);
	}

	const unexpectedQuarantine = results.filter(
		(r) => !r.scenario.expectedQuarantined && r.quarantined,
	);
	for (const r of unexpectedQuarantine) {
		weaknesses.push(`"${r.scenario.name}" triggered unexpected quarantine`);
	}

	const missedQuarantine = results.filter(
		(r) => r.scenario.expectedQuarantined && !r.quarantined,
	);
	for (const r of missedQuarantine) {
		weaknesses.push(
			`"${r.scenario.name}" should have triggered quarantine but did not`,
		);
	}

	return weaknesses;
}

export function formatPolicyTestReport(result: PolicyTestResult): string {
	const lines: string[] = [];

	lines.push(`\n${CYAN}${BOLD}Policy Test Report${RESET}`);
	lines.push(`${DIM}Policy: ${result.policySource}${RESET}`);
	lines.push(`${"=".repeat(60)}\n`);

	for (const r of result.scenarios) {
		const icon = r.passed ? `${GREEN}PASS${RESET}` : `${RED}FAIL${RESET}`;
		const blocked = r.blocked
			? `${RED}blocked at step ${r.blockedAtStep}${RESET}`
			: `${GREEN}all steps allowed${RESET}`;
		lines.push(`[${icon}] ${r.scenario.name}`);
		lines.push(`  ${DIM}${r.scenario.description}${RESET}`);
		lines.push(`  ${DIM}Result: ${blocked}${RESET}`);
		if (r.quarantined) {
			lines.push(`  ${MAGENTA}Quarantined${RESET}`);
		}
		lines.push("");
	}

	lines.push(`${"=".repeat(60)}`);
	lines.push(
		`${BOLD}Results: ${GREEN}${result.passed} passed${RESET}, ${RED}${result.failed} failed${RESET} ` +
			`${DIM}(${result.scenarios.length} scenarios)${RESET}`,
	);
	lines.push(
		`${DIM}Blocked: ${result.blocked} | Allowed through: ${result.allowed}${RESET}`,
	);

	if (result.weaknesses.length > 0) {
		lines.push(`\n${RED}${BOLD}Policy Weaknesses:${RESET}`);
		for (const w of result.weaknesses) {
			lines.push(`  ${YELLOW}⚠ ${w}${RESET}`);
		}
	} else {
		lines.push(
			`\n${GREEN}${BOLD}No weaknesses detected — all scenarios matched expectations.${RESET}`,
		);
	}

	lines.push("");
	return lines.join("\n");
}

// ── Permissive sim firewall for YAML scenarios ──────────────────────
//
// Unlike the narrow sim firewall in simulate.ts (which tests capability
// constraints), YAML scenarios are designed to exercise policy rules.
// We grant broad capabilities so the *policy engine* decides enforcement.

function createYamlSimFirewall(policies: string | PolicyRule[]): Firewall {
	return createFirewall({
		principal: {
			name: "yaml-sim-agent",
			capabilities: [
				{
					toolClass: "http",
					actions: ["get", "post", "put", "delete"],
				},
				{
					toolClass: "file",
					actions: ["read", "write"],
				},
				{
					toolClass: "shell",
					actions: ["exec"],
				},
				{
					toolClass: "database",
					actions: ["query", "exec", "mutate"],
				},
			],
		},
		policies,
		auditLog: ":memory:",
		runStatePolicy: {
			maxDeniedSensitiveActions: 5,
			behavioralRules: true,
		},
	});
}

function registerStubExecutors(fw: Firewall): void {
	fw.registerExecutor({
		toolClass: "http",
		async execute(tc) {
			const url = String(tc.parameters.url ?? "");
			let hostname = url;
			try {
				hostname = new URL(url).hostname;
			} catch {
				/* use raw url as origin */
			}
			return {
				callId: tc.id,
				success: true,
				data: { body: `response from ${url}` },
				durationMs: 5,
				taintLabels: [
					{
						source: "web" as const,
						origin: hostname,
						confidence: 1.0,
						addedAt: new Date().toISOString(),
					},
				],
			};
		},
	});
	fw.registerExecutor({
		toolClass: "file",
		async execute(tc) {
			return {
				callId: tc.id,
				success: true,
				data: { content: `contents of ${tc.parameters.path}` },
				durationMs: 3,
				taintLabels: [],
			};
		},
	});
	fw.registerExecutor({
		toolClass: "shell",
		async execute(tc) {
			return {
				callId: tc.id,
				success: true,
				data: { stdout: "command output" },
				durationMs: 10,
				taintLabels: [],
			};
		},
	});
	fw.registerExecutor({
		toolClass: "database",
		async execute(tc) {
			return {
				callId: tc.id,
				success: true,
				data: { rows: [] },
				durationMs: 5,
				taintLabels: [],
			};
		},
	});
}

/**
 * Execute a YAML attack scenario through the kernel with broad capabilities.
 * This lets the policy engine (not capability constraints) decide enforcement.
 */
async function executeYamlScenario(
	scenario: AttackScenario,
	policies: string | PolicyRule[],
): Promise<AttackResult> {
	const fw = createYamlSimFirewall(policies);
	registerStubExecutors(fw);

	const stepVerdicts: StepVerdict[] = [];
	let blockedAtStep = -1;
	let blockReason = "";

	try {
		for (let i = 0; i < scenario.steps.length; i++) {
			const step = scenario.steps[i];

			if (step.capabilityClass) {
				const grant = fw.requestCapability(step.capabilityClass as CapabilityClass);
				if (!grant.granted) {
					blockedAtStep = i + 1;
					blockReason = grant.reason ?? "Capability denied";
					stepVerdicts.push({ step, verdict: "capability-denied", reason: blockReason });
					break;
				}

				try {
					await fw.execute({ ...step.request, grantId: grant.grant?.id });
					stepVerdicts.push({ step, verdict: "allow", reason: "Allowed" });
				} catch (err) {
					blockedAtStep = i + 1;
					blockReason =
						err instanceof ToolCallDeniedError
							? err.decision.reason
							: err instanceof Error
								? err.message
								: String(err);
					stepVerdicts.push({ step, verdict: "deny", reason: blockReason });
					break;
				}
			} else {
				try {
					await fw.execute(step.request);
					stepVerdicts.push({ step, verdict: "allow", reason: "Allowed" });
				} catch (err) {
					blockedAtStep = i + 1;
					blockReason =
						err instanceof ToolCallDeniedError
							? err.decision.reason
							: err instanceof Error
								? err.message
								: String(err);
					stepVerdicts.push({ step, verdict: "deny", reason: blockReason });
					break;
				}
			}
		}

		const blocked = blockedAtStep > 0;
		const quarantined = fw.isRestricted;
		const auditEvents = fw.getEvents();
		const passed =
			blocked === scenario.expectedBlocked && quarantined === scenario.expectedQuarantined;

		return {
			scenario,
			blocked,
			blockedAtStep,
			blockReason,
			quarantined,
			stepVerdicts,
			auditEvents,
			runId: fw.runId,
			passed,
		};
	} finally {
		fw.close();
	}
}

// ── Core runner functions ────────────────────────────────────────────

export interface RunScenarioOptions {
	policies?: string | PolicyRule[];
	showTimeline?: boolean;
}

/**
 * Run a single YAML scenario file through the kernel.
 */
export async function runScenarioFile(
	filePath: string,
	options?: RunScenarioOptions,
): Promise<AttackResult[]> {
	const scenarios = loadScenarioFile(filePath);
	return runScenarios(scenarios, options);
}

/**
 * Run all YAML scenarios in a directory through the kernel.
 */
export async function runScenarioDirectory(
	dirPath: string,
	options?: RunScenarioOptions,
): Promise<AttackResult[]> {
	const scenarios = loadScenarioDirectory(dirPath);
	return runScenarios(scenarios, options);
}

async function runScenarios(
	scenarios: AttackScenario[],
	options?: RunScenarioOptions,
): Promise<AttackResult[]> {
	const policies = options?.policies ?? DEFAULT_POLICY;
	const results: AttackResult[] = [];

	for (const scenario of scenarios) {
		const result = await executeYamlScenario(scenario, policies);
		results.push(result);

		if (options?.showTimeline) {
			console.log(formatTimeline(result));
		}
	}
	return results;
}

/**
 * Run policy tests: execute scenarios and produce a report with weakness analysis.
 */
export async function runPolicyTest(
	policySource: string | PolicyRule[],
	scenarioPath: string,
): Promise<PolicyTestResult> {
	const policyLabel = typeof policySource === "string" ? policySource : "inline-rules";
	const scenarios = loadScenarioDirectory(scenarioPath);
	const results: AttackResult[] = [];

	for (const scenario of scenarios) {
		results.push(await executeYamlScenario(scenario, policySource));
	}

	const blocked = results.filter((r) => r.blocked).length;
	const allowed = results.length - blocked;
	const passed = results.filter((r) => r.passed).length;
	const failed = results.length - passed;
	const weaknesses = identifyWeaknesses(results);

	return {
		policySource: policyLabel,
		scenarios: results,
		blocked,
		allowed,
		passed,
		failed,
		weaknesses,
	};
}
