import type {
	AuditEvent,
	CapabilityClass,
	DecisionVerdict,
	PolicyRule,
	ToolCallRequest,
} from "@arikernel/core";
import { ToolCallDeniedError } from "@arikernel/core";
import { type Firewall, createFirewall } from "@arikernel/runtime";
import { DEFAULT_POLICY } from "./default-policy.js";

// ── Types ─────────────────────────────────────────────────────────────

export interface AttackStep {
	label: string;
	request: ToolCallRequest;
	capabilityClass?: CapabilityClass;
}

export interface AttackScenario {
	name: string;
	description: string;
	/** The prompt an attacker or injected instruction would use. */
	attackPrompt: string;
	/** What the agent is expected to do in response. */
	expectedAgentBehavior: string;
	/** How the kernel should respond. */
	expectedKernelResponse: string;
	/** Ordered tool-call steps the attack would attempt. */
	steps: AttackStep[];
	/** Whether the kernel should block at least one step. */
	expectedBlocked: boolean;
	/** Whether the run should enter quarantine. */
	expectedQuarantined: boolean;
}

export interface AttackResult {
	scenario: AttackScenario;
	/** Whether the kernel blocked the attack (at least one step denied). */
	blocked: boolean;
	/** 1-based index of the step that was blocked, or -1 if all passed. */
	blockedAtStep: number;
	/** Reason the step was blocked. */
	blockReason: string;
	/** Whether the run entered quarantine. */
	quarantined: boolean;
	/** Verdicts for each step attempted. */
	stepVerdicts: StepVerdict[];
	/** Audit events recorded during the simulation. */
	auditEvents: AuditEvent[];
	/** The firewall run ID for trace replay. */
	runId: string;
	/** Whether the result matches expectations. */
	passed: boolean;
}

export interface StepVerdict {
	step: AttackStep;
	verdict: DecisionVerdict | "capability-denied";
	reason: string;
}

// ── Agent interface ───────────────────────────────────────────────────

/**
 * Minimal agent interface for simulation.
 *
 * An "agent" here is anything that can decide whether to proceed with
 * a tool call. The simplest agent always proceeds (used by default).
 * Developers can provide smarter agents that parse the attack prompt
 * and make decisions.
 */
export interface SimAgent {
	/** Called before each step. Return true to proceed, false to skip. */
	shouldProceed(step: AttackStep, stepIndex: number, scenario: AttackScenario): boolean;
}

const ALWAYS_PROCEED: SimAgent = {
	shouldProceed: () => true,
};

// ── Options ───────────────────────────────────────────────────────────

export interface SimulateAttackOptions {
	policies?: string | PolicyRule[];
	/** Custom agent that decides whether to proceed with each step. */
	agent?: SimAgent;
}

// ── Core helper ───────────────────────────────────────────────────────

function createSimFirewall(policies: string | PolicyRule[]): Firewall {
	return createFirewall({
		principal: {
			name: "sim-agent",
			capabilities: [
				{
					toolClass: "http",
					actions: ["get"],
					constraints: { allowedHosts: ["api.github.com", "httpbin.org", "malicious-site.com"] },
				},
				{
					toolClass: "file",
					actions: ["read"],
					constraints: { allowedPaths: ["./data/**"] },
				},
				{
					toolClass: "database",
					actions: ["query"],
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
			// Produce web taint from URL hostname, matching real HTTP executor behavior.
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
 * Simulate an attack scenario against the Ari Kernel.
 *
 * Walks through each step in the scenario, requesting capabilities and
 * executing tool calls through a real firewall instance. Records verdicts,
 * audit events, and quarantine state.
 *
 * @param scenario - The attack scenario to simulate
 * @param options  - Optional policies and agent
 * @returns Full attack result with verdicts, audit trail, and pass/fail
 */
export async function simulateAttack(
	scenario: AttackScenario,
	options?: SimulateAttackOptions,
): Promise<AttackResult> {
	const agent = options?.agent ?? ALWAYS_PROCEED;
	const fw = createSimFirewall(options?.policies ?? DEFAULT_POLICY);
	registerStubExecutors(fw);

	const stepVerdicts: StepVerdict[] = [];
	let blockedAtStep = -1;
	let blockReason = "";

	try {
		for (let i = 0; i < scenario.steps.length; i++) {
			const step = scenario.steps[i];

			// Let the agent decide whether to proceed
			if (!agent.shouldProceed(step, i, scenario)) {
				stepVerdicts.push({
					step,
					verdict: "allow",
					reason: "Agent chose to skip this step",
				});
				continue;
			}

			// Request capability if specified
			if (step.capabilityClass) {
				const grant = fw.requestCapability(step.capabilityClass);
				if (!grant.granted) {
					blockedAtStep = i + 1;
					blockReason = grant.reason ?? "Capability denied";
					stepVerdicts.push({
						step,
						verdict: "capability-denied",
						reason: blockReason,
					});
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

/**
 * Simulate multiple attack scenarios and return all results.
 */
export async function simulateAll(
	scenarios: AttackScenario[],
	options?: SimulateAttackOptions,
): Promise<AttackResult[]> {
	const results: AttackResult[] = [];
	for (const scenario of scenarios) {
		results.push(await simulateAttack(scenario, options));
	}
	return results;
}
