import { loadPolicyFile } from '@arikernel/policy-engine';

export function runPolicyValidate(filePath: string): void {
	try {
		const rules = loadPolicyFile(filePath);
		console.log(`Policy file is valid: ${filePath}`);
		console.log(`  Rules: ${rules.length}`);

		for (const rule of rules) {
			console.log(`  - [${rule.priority}] ${rule.name} -> ${rule.decision}`);
		}
	} catch (err) {
		console.error(`Policy validation failed: ${err instanceof Error ? err.message : err}`);
		process.exit(1);
	}
}
