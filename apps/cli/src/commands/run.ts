import { createFirewall } from '@agent-firewall/runtime';
import { printDecision } from '../output.js';

export async function runAgent(policyPath: string, auditPath: string): Promise<void> {
	const firewall = createFirewall({
		principal: {
			name: 'cli-agent',
			capabilities: [
				{ toolClass: 'http', actions: ['get'] },
				{ toolClass: 'file', actions: ['read', 'write'] },
			],
		},
		policies: policyPath,
		auditLog: auditPath,
		hooks: {
			onDecision: (toolCall, decision) => {
				printDecision(toolCall, decision);
			},
			onApprovalRequired: async (_toolCall, _decision) => {
				// In CLI mode, auto-deny approval requests
				console.log('  Auto-denying approval request in non-interactive mode.');
				return false;
			},
		},
	});

	console.log(`Firewall started. Run ID: ${firewall.runId}`);
	console.log('Ready to intercept tool calls.\n');

	// This is a placeholder. Real usage: the agent sends tool calls through firewall.execute()
	firewall.close();
}
