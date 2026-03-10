import type { DecisionVerdict, PolicyRule, ToolCallRequest } from "@arikernel/core";
import { ToolCallDeniedError } from "@arikernel/core";
import { createFirewall } from "@arikernel/runtime";
import { DEFAULT_POLICY } from "./default-policy.js";
import { dataExfiltrationScenarios } from "./scenarios/data-exfiltration.js";
import { filesystemTraversalScenarios } from "./scenarios/filesystem-traversal.js";
import { privilegeEscalationScenarios } from "./scenarios/privilege-escalation.js";
import { promptInjectionScenarios } from "./scenarios/prompt-injection.js";
import { ssrfScenarios } from "./scenarios/ssrf.js";
import { toolEscalationScenarios } from "./scenarios/tool-escalation.js";
import { toolMisuseScenarios } from "./scenarios/tool-misuse.js";

export interface SimScenario {
	name: string;
	description: string;
	/** The attack prompt that triggers this behavior. */
	attackPrompt?: string;
	/** What the agent is expected to do. */
	expectedAgentBehavior?: string;
	/** How the kernel should respond. */
	expectedKernelResponse?: string;
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
	...ssrfScenarios,
	...filesystemTraversalScenarios,
	...toolEscalationScenarios,
];

export async function runSimulation(policies?: string | PolicyRule[]): Promise<SimResult[]> {
	const results: SimResult[] = [];

	for (const scenario of ALL_SCENARIOS) {
		const firewall = createFirewall({
			principal: {
				name: "sim-agent",
				capabilities: [
					{
						toolClass: "http",
						actions: ["get"],
						constraints: { allowedHosts: ["api.github.com"] },
					},
					{ toolClass: "file", actions: ["read"], constraints: { allowedPaths: ["./data/**"] } },
				],
			},
			policies: policies ?? DEFAULT_POLICY,
			auditLog: ":memory:",
		});

		try {
			await firewall.execute(scenario.request);
			results.push({
				scenario,
				actualVerdict: "allow",
				passed: scenario.expectedVerdict === "allow",
			});
		} catch (err) {
			if (err instanceof ToolCallDeniedError) {
				results.push({
					scenario,
					actualVerdict: "deny",
					passed: scenario.expectedVerdict === "deny",
				});
			} else {
				results.push({
					scenario,
					actualVerdict: "deny",
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
