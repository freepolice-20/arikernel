import { describe, expect, it } from "vitest";
import {
	simulateAttack,
	simulateAll,
	type AttackScenario,
} from "../src/simulate.js";
import { multiStepExfiltrationScenarios } from "../src/scenarios/multi-step-exfiltration.js";
import { ssrfScenarios } from "../src/scenarios/ssrf.js";
import { filesystemTraversalScenarios } from "../src/scenarios/filesystem-traversal.js";
import { toolEscalationScenarios } from "../src/scenarios/tool-escalation.js";

// ── Single-step scenarios via simulateAttack ──────────────────────────

describe("simulateAttack - single-step scenarios", () => {
	describe("SSRF scenarios", () => {
		const singleStepSsrf: AttackScenario[] = ssrfScenarios.map((s) => ({
			name: s.name,
			description: s.description,
			attackPrompt: s.attackPrompt ?? s.description,
			expectedAgentBehavior: s.expectedAgentBehavior ?? "Agent makes HTTP request",
			expectedKernelResponse: s.expectedKernelResponse ?? "Kernel denies",
			steps: [
				{
					label: s.name,
					request: s.request,
					capabilityClass: "http.read" as const,
				},
			],
			expectedBlocked: true,
			expectedQuarantined: false,
		}));

		for (const scenario of singleStepSsrf) {
			it(`blocks: ${scenario.name}`, async () => {
				const result = await simulateAttack(scenario);
				expect(result.blocked).toBe(true);
				expect(result.blockedAtStep).toBeGreaterThan(0);
			});
		}
	});

	describe("filesystem traversal scenarios", () => {
		const singleStepFs: AttackScenario[] = filesystemTraversalScenarios.map((s) => ({
			name: s.name,
			description: s.description,
			attackPrompt: s.attackPrompt ?? s.description,
			expectedAgentBehavior: s.expectedAgentBehavior ?? "Agent reads file",
			expectedKernelResponse: s.expectedKernelResponse ?? "Kernel denies",
			steps: [
				{
					label: s.name,
					request: s.request,
					capabilityClass: s.request.action === "write"
						? ("file.write" as const)
						: ("file.read" as const),
				},
			],
			expectedBlocked: true,
			expectedQuarantined: false,
		}));

		for (const scenario of singleStepFs) {
			it(`blocks: ${scenario.name}`, async () => {
				const result = await simulateAttack(scenario);
				expect(result.blocked).toBe(true);
			});
		}
	});

	describe("tool escalation scenarios", () => {
		const singleStepEsc: AttackScenario[] = toolEscalationScenarios.map((s) => ({
			name: s.name,
			description: s.description,
			attackPrompt: s.attackPrompt ?? s.description,
			expectedAgentBehavior: s.expectedAgentBehavior ?? "Agent escalates",
			expectedKernelResponse: s.expectedKernelResponse ?? "Kernel denies",
			steps: [
				{
					label: s.name,
					request: s.request,
					capabilityClass:
						s.request.toolClass === "shell"
							? ("shell.exec" as const)
							: s.request.toolClass === "database"
								? ("database.write" as const)
								: s.request.action === "post"
									? ("http.write" as const)
									: ("file.write" as const),
				},
			],
			expectedBlocked: true,
			expectedQuarantined: false,
		}));

		for (const scenario of singleStepEsc) {
			it(`blocks: ${scenario.name}`, async () => {
				const result = await simulateAttack(scenario);
				expect(result.blocked).toBe(true);
			});
		}
	});
});

// ── Multi-step scenarios ──────────────────────────────────────────────

describe("simulateAttack - multi-step exfiltration", () => {
	for (const scenario of multiStepExfiltrationScenarios) {
		it(`blocks: ${scenario.name}`, async () => {
			const result = await simulateAttack(scenario);
			expect(result.blocked).toBe(scenario.expectedBlocked);
			expect(result.passed).toBe(true);
		});
	}
});

// ── Audit log verification ────────────────────────────────────────────

describe("audit log records attack events", () => {
	it("records audit events for each attempted step", async () => {
		const scenario = multiStepExfiltrationScenarios[0];
		const result = await simulateAttack(scenario);

		// At least one audit event should be recorded
		expect(result.auditEvents.length).toBeGreaterThan(0);
		expect(result.runId).toBeTruthy();
	});

	it("audit events include deny verdicts for blocked attacks", async () => {
		// Use a scenario that is definitely blocked
		const scenario = multiStepExfiltrationScenarios[1]; // web taint then credential theft
		const result = await simulateAttack(scenario);

		expect(result.blocked).toBe(true);
		// stepVerdicts should include a deny or capability-denied
		const denials = result.stepVerdicts.filter(
			(sv) => sv.verdict === "deny" || sv.verdict === "capability-denied",
		);
		expect(denials.length).toBeGreaterThan(0);
	});
});

// ── Trace replay verification ─────────────────────────────────────────

describe("trace replay reproduces result", () => {
	it("audit events are consistent with step verdicts", async () => {
		const scenario = multiStepExfiltrationScenarios[0];
		const result = await simulateAttack(scenario);

		// The number of audit events should be at least the number of allowed steps
		const allowedSteps = result.stepVerdicts.filter((sv) => sv.verdict === "allow");
		// Each allowed step produces at least one audit event
		expect(result.auditEvents.length).toBeGreaterThanOrEqual(allowedSteps.length);

		// Verify the run ID is stable and all events belong to the same run
		for (const event of result.auditEvents) {
			expect(event.runId).toBe(result.runId);
		}
	});
});

// ── simulateAll ───────────────────────────────────────────────────────

describe("simulateAll", () => {
	it("runs all multi-step scenarios and returns results", async () => {
		const results = await simulateAll(multiStepExfiltrationScenarios);
		expect(results.length).toBe(multiStepExfiltrationScenarios.length);

		for (const result of results) {
			expect(result.blocked).toBe(result.scenario.expectedBlocked);
		}
	});
});

// ── SimAgent interface ────────────────────────────────────────────────

describe("SimAgent integration", () => {
	it("agent that skips all steps results in no blocks", async () => {
		const scenario = multiStepExfiltrationScenarios[0];
		const result = await simulateAttack(scenario, {
			agent: { shouldProceed: () => false },
		});

		expect(result.blocked).toBe(false);
		expect(result.stepVerdicts.every((sv) => sv.verdict === "allow")).toBe(true);
	});
});
