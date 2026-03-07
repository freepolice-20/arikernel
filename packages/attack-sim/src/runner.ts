import type { DecisionVerdict, ToolCallRequest } from '@arikernel/core';
import { ToolCallDeniedError } from '@arikernel/core';
import { createFirewall } from '@arikernel/runtime';
import { promptInjectionScenarios } from './scenarios/prompt-injection.js';
import { toolMisuseScenarios } from './scenarios/tool-misuse.js';
import { dataExfiltrationScenarios } from './scenarios/data-exfiltration.js';
import { privilegeEscalationScenarios } from './scenarios/privilege-escalation.js';

export interface SimScenario {
	name: string;
	description: string;
	request: ToolCallRequest;
	expectedVerdict: DecisionVerdict;
}

export interface SimResult {
	scenario: SimScenario;
	actualVerdict: DecisionVerdict;
	passed: boolean;
	error?: string;
}

const ALL_SCENARIOS: SimScenario[] = [
	...promptInjectionScenarios,
	...toolMisuseScenarios,
	...dataExfiltrationScenarios,
	...privilegeEscalationScenarios,
];

export async function runSimulation(
	policies: string,
): Promise<SimResult[]> {
	const results: SimResult[] = [];

	for (const scenario of ALL_SCENARIOS) {
		const firewall = createFirewall({
			principal: {
				name: 'sim-agent',
				capabilities: [
					{ toolClass: 'http', actions: ['get'], constraints: { allowedHosts: ['api.github.com'] } },
					{ toolClass: 'file', actions: ['read'], constraints: { allowedPaths: ['./data/**'] } },
				],
			},
			policies,
			auditLog: ':memory:',
		});

		try {
			await firewall.execute(scenario.request);
			results.push({
				scenario,
				actualVerdict: 'allow',
				passed: scenario.expectedVerdict === 'allow',
			});
		} catch (err) {
			if (err instanceof ToolCallDeniedError) {
				results.push({
					scenario,
					actualVerdict: 'deny',
					passed: scenario.expectedVerdict === 'deny',
				});
			} else {
				results.push({
					scenario,
					actualVerdict: 'deny',
					passed: false,
					error: err instanceof Error ? err.message : String(err),
				});
			}
		} finally {
			firewall.close();
		}
	}

	return results;
}
