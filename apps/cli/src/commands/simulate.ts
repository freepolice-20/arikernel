import { resolve } from "node:path";
import {
	ATTACK_TYPES,
	DEFAULT_AUDIT_DB,
	generateReport,
	runInteractive,
	runSimulation,
} from "@arikernel/attack-sim";
import type { AttackType } from "@arikernel/attack-sim";

const DIM = "\x1b[2m";
const BOLD = "\x1b[1m";
const CYAN = "\x1b[36m";
const RESET = "\x1b[0m";

export async function runSimulate(
	policyPath?: string,
	attackType?: string,
	dbPath?: string,
): Promise<void> {
	const policies = policyPath || undefined;
	const auditLog = dbPath ?? DEFAULT_AUDIT_DB;

	if (attackType) {
		if (!ATTACK_TYPES.includes(attackType as AttackType)) {
			console.error(`Unknown attack type: ${attackType}`);
			console.error(`Valid types: ${ATTACK_TYPES.join(", ")}`);
			process.exit(1);
		}
		const result = await runInteractive(attackType as AttackType, { policies, auditLog });
		printForensicInfo(auditLog, result.runId);
	} else {
		console.log("Running attack simulation pack...\n");
		const results = await runSimulation(policies);
		const report = generateReport(results);
		console.log(report);
	}
}

function printForensicInfo(auditLog: string, runId: string): void {
	const absPath = resolve(auditLog);
	console.log(`${CYAN}${BOLD}Forensic data${RESET}`);
	console.log(`  ${DIM}Audit DB:${RESET} ${absPath}`);
	console.log(`  ${DIM}Run ID:${RESET}   ${runId}`);
	console.log("");
	console.log(`${DIM}Replay this run:${RESET}`);
	console.log(`  arikernel trace --latest --db ${auditLog}`);
	console.log(`  arikernel replay --latest --db ${auditLog}`);
	console.log("");
}
