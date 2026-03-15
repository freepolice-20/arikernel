/**
 * Attack Simulation Demo — Integration with demo-real-agent
 *
 * Runs all attack simulation scenarios against the Ari Kernel and prints
 * a summary report. This demonstrates how to integrate the attack-sim
 * library into your agent testing workflow.
 *
 * Run:  npx tsx examples/demo-real-agent/attack-sim-demo.ts
 */

import { resolve } from "node:path";
import {
	type AttackResult,
	type AttackScenario,
	generateReport,
	multiStepExfiltrationScenarios,
	runSimulation,
	simulateAll,
	simulateAttack,
} from "@arikernel/attack-sim";

// ── Colors ────────────────────────────────────────────────────────────

const B = "\x1b[1m";
const D = "\x1b[2m";
const G = "\x1b[32m";
const R = "\x1b[31m";
const C = "\x1b[36m";
const M = "\x1b[35m";
const Y = "\x1b[33m";
const X = "\x1b[0m";

const line = (n: number) => "━".repeat(n);

// ── Helpers ───────────────────────────────────────────────────────────

function printResult(result: AttackResult): void {
	const status = result.blocked ? `${G}BLOCKED${X}` : `${R}NOT BLOCKED${X}`;
	const quarantine = result.quarantined ? ` ${M}[quarantined]${X}` : "";
	const pass = result.passed ? `${G}PASS${X}` : `${R}FAIL${X}`;

	console.log(`  [${pass}] ${B}${result.scenario.name}${X}`);
	console.log(`    ${D}Attack: ${result.scenario.attackPrompt}${X}`);
	console.log(`    ${D}Result: ${status}${quarantine}${X}`);

	if (result.blocked) {
		console.log(`    ${D}Blocked at step ${result.blockedAtStep}: ${result.blockReason}${X}`);
	}

	for (const sv of result.stepVerdicts) {
		const icon = sv.verdict === "allow" ? `${G}✓${X}` : `${R}✗${X}`;
		console.log(`    ${icon} ${sv.step.label} → ${sv.verdict}`);
	}

	console.log(`    ${D}Audit events: ${result.auditEvents.length} | Run: ${result.runId}${X}`);
	console.log();
}

// ── Main ──────────────────────────────────────────────────────────────

async function main() {
	const policyPath = resolve(
		import.meta.dirname ?? ".",
		"..",
		"..",
		"policies",
		"safe-defaults.yaml",
	);

	console.log(`\n${C}${B}${line(64)}${X}`);
	console.log(`${C}${B}  Ari Kernel  Attack Simulation Demo${X}`);
	console.log(`${C}${B}${line(64)}${X}\n`);

	// ── Part 1: Single-step scenarios (original runner) ─────────────

	console.log(`${Y}${B}Part 1: Single-step attack scenarios${X}\n`);

	const singleStepResults = await runSimulation(policyPath);
	console.log(generateReport(singleStepResults));

	// ── Part 2: Multi-step exfiltration scenarios ────────────────────

	console.log(`\n${Y}${B}Part 2: Multi-step exfiltration scenarios${X}\n`);

	const multiStepResults = await simulateAll(multiStepExfiltrationScenarios);

	for (const result of multiStepResults) {
		printResult(result);
	}

	// ── Summary ──────────────────────────────────────────────────────

	const totalSingle = singleStepResults.length;
	const passedSingle = singleStepResults.filter((r) => r.passed).length;
	const totalMulti = multiStepResults.length;
	const passedMulti = multiStepResults.filter((r) => r.passed).length;

	console.log(`${C}${B}${line(64)}${X}`);
	console.log(`${C}${B}  Summary${X}`);
	console.log(`${C}${B}${line(64)}${X}`);
	console.log(`  Single-step: ${G}${passedSingle}/${totalSingle} passed${X}`);
	console.log(`  Multi-step:  ${G}${passedMulti}/${totalMulti} passed${X}`);

	const allPassed = passedSingle === totalSingle && passedMulti === totalMulti;
	if (allPassed) {
		console.log(`\n  ${G}${B}All attack scenarios correctly handled.${X}\n`);
	} else {
		console.log(`\n  ${R}${B}Some scenarios were not blocked — review your policies.${X}\n`);
		process.exit(1);
	}
}

main().catch((err) => {
	console.error(`\n${R}${B}Error:${X} ${err.message}\n`);
	process.exit(1);
});
