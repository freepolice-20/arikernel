import type { SimResult } from './runner.js';

const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';

export function generateReport(results: SimResult[]): string {
	const lines: string[] = [];
	const passed = results.filter((r) => r.passed).length;
	const failed = results.filter((r) => !r.passed).length;

	lines.push(`${BOLD}Attack Simulation Report${RESET}`);
	lines.push(`${'='.repeat(50)}\n`);

	for (const result of results) {
		const icon = result.passed ? `${GREEN}PASS${RESET}` : `${RED}FAIL${RESET}`;
		lines.push(`[${icon}] ${result.scenario.name}`);
		lines.push(`  ${DIM}${result.scenario.description}${RESET}`);
		lines.push(
			`  ${DIM}Expected: ${result.scenario.expectedVerdict} | Actual: ${result.actualVerdict}${RESET}`,
		);

		if (result.error) {
			lines.push(`  ${RED}Error: ${result.error}${RESET}`);
		}

		lines.push('');
	}

	lines.push(`${'='.repeat(50)}`);
	lines.push(`${BOLD}Results: ${GREEN}${passed} passed${RESET}, ${RED}${failed} failed${RESET} ${DIM}(${results.length} total)${RESET}`);

	if (failed === 0) {
		lines.push(`\n${GREEN}${BOLD}All attack scenarios were correctly handled.${RESET}`);
	} else {
		lines.push(`\n${RED}${BOLD}WARNING: ${failed} attack scenario(s) were not blocked!${RESET}`);
	}

	return lines.join('\n');
}
