import { resolve } from "node:path";
import {
	BUILTIN_SCENARIOS_DIR,
	formatPolicyTestReport,
	runPolicyTest,
} from "@arikernel/attack-sim";
import { loadPolicies } from "@arikernel/policy-engine";

const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const CYAN = "\x1b[36m";
const RESET = "\x1b[0m";

export async function runPolicyTestCommand(
	policyPath: string,
	scenariosPath?: string,
): Promise<void> {
	const policies = loadPolicies(policyPath);
	const scenarioDir = scenariosPath ? resolve(scenariosPath) : BUILTIN_SCENARIOS_DIR;

	console.log(`\n${CYAN}${BOLD}Policy Test${RESET}`);
	console.log(`${DIM}Policy:    ${resolve(policyPath)}${RESET}`);
	console.log(`${DIM}Scenarios: ${scenarioDir}${RESET}\n`);

	const result = await runPolicyTest(policies, scenarioDir);
	result.policySource = resolve(policyPath);

	console.log(formatPolicyTestReport(result));

	if (result.failed > 0) {
		process.exitCode = 1;
	}
}
