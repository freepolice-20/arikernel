import { relative, resolve } from "node:path";
import {
	BUILTIN_SCENARIOS_DIR,
	formatTimeline,
	loadBuiltinScenarios,
	runScenarioFile,
} from "@arikernel/attack-sim";
import { loadPolicies } from "@arikernel/policy-engine";

const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const CYAN = "\x1b[36m";
const RESET = "\x1b[0m";

export async function runAttackSimulate(scenarioPath: string, policyPath?: string): Promise<void> {
	const abs = resolve(scenarioPath);
	const policies = policyPath ? loadPolicies(policyPath) : undefined;

	console.log(`\n${CYAN}${BOLD}Attack Simulation${RESET}`);
	console.log(`${DIM}Scenario: ${relative(process.cwd(), abs)}${RESET}`);
	if (policyPath) {
		console.log(`${DIM}Policy:   ${relative(process.cwd(), resolve(policyPath))}${RESET}`);
	}
	console.log("");

	const results = await runScenarioFile(abs, { policies, showTimeline: false });

	for (const result of results) {
		console.log(formatTimeline(result));
	}

	// Summary
	const blocked = results.filter((r) => r.blocked).length;
	const total = results.length;
	console.log(`${BOLD}Summary: ${blocked}/${total} attacks blocked${RESET}`);

	if (blocked < total) {
		const unblocked = results.filter((r) => !r.blocked);
		console.log(`\n${RED}${BOLD}Unblocked attacks:${RESET}`);
		for (const r of unblocked) {
			console.log(`  ${RED}- ${r.scenario.name}${RESET}`);
		}
	}

	console.log("");
}

export async function runAttackList(): Promise<void> {
	console.log(`\n${CYAN}${BOLD}Built-in Attack Scenarios${RESET}`);
	console.log(`${DIM}Location: ${relative(process.cwd(), BUILTIN_SCENARIOS_DIR)}${RESET}\n`);

	const scenarios = loadBuiltinScenarios();
	for (const s of scenarios) {
		const tags = (s as unknown as { tags?: string[] }).tags;
		console.log(`  ${BOLD}${s.name}${RESET}`);
		console.log(`  ${DIM}${s.description}${RESET}`);
		console.log(
			`  ${DIM}Steps: ${s.steps.length} | Expected blocked: ${s.expectedBlocked}${RESET}`,
		);
		if (tags) {
			console.log(`  ${DIM}Tags: ${tags.join(", ")}${RESET}`);
		}
		console.log("");
	}
}
