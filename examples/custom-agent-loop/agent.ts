/**
 * Custom Agent Loop — AriKernel Integration Example
 *
 * Demonstrates that AriKernel works with any model (OpenAI, Claude, Gemini, etc.)
 * because it protects the tool execution boundary, not the model itself.
 *
 * This example simulates a generic agent loop where:
 * 1. A model selects a tool and arguments
 * 2. The tool map routes execution through AriKernel
 * 3. AriKernel enforces capabilities, policies, and behavioral rules
 * 4. The result is returned to the model
 *
 * Run:
 *   npx tsx examples/custom-agent-loop/agent.ts
 *   arikernel trace --latest
 *   arikernel replay --latest --step
 */

import { ToolCallDeniedError } from '@arikernel/core';
import type { ToolCallRequest } from '@arikernel/core';
import { createFirewall } from '@arikernel/runtime';
import { resolve } from 'node:path';

// ── Inline protectTools (same as @arikernel/adapters protectTools) ───

function protectTools(
	firewall: ReturnType<typeof createFirewall>,
	mappings: Record<string, { toolClass: string; action: string }>,
) {
	const result: Record<string, (args: Record<string, unknown>) => Promise<any>> = {};
	for (const [name, mapping] of Object.entries(mappings)) {
		result[name] = async (parameters: Record<string, unknown>) => {
			const isRead = ['get', 'read', 'query', 'list'].includes(mapping.action);
			const capClass = `${mapping.toolClass}.${isRead ? 'read' : 'write'}`;
			const grant = firewall.requestCapability(capClass as any);
			if (!grant.granted) throw new Error(grant.reason ?? 'Capability denied');
			return firewall.execute({
				toolClass: mapping.toolClass as ToolCallRequest['toolClass'],
				action: mapping.action, parameters,
				grantId: grant.grant!.id,
			});
		};
	}
	return result;
}

// ── Colors ──────────────────────────────────────────────────────────

const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const RESET = '\x1b[0m';

// ── Simulated model responses ───────────────────────────────────────
// These represent tool-use decisions from any model — OpenAI, Claude, etc.

const MODEL_TOOL_CALLS = [
	{ tool: 'web_search', args: { url: 'https://api.example.com/data' }, description: 'Search the web' },
	{ tool: 'read_file', args: { path: './data/notes.txt' }, description: 'Read allowed file' },
	{ tool: 'read_file', args: { path: '/etc/shadow' }, description: 'Read sensitive file' },
	{ tool: 'run_shell', args: { command: 'whoami' }, description: 'Execute shell command' },
];

// ── Agent loop ──────────────────────────────────────────────────────

async function runAgentLoop() {
	const auditDb = resolve('arikernel-audit.db');

	const firewall = createFirewall({
		principal: {
			name: 'custom-agent',
			capabilities: [
				{ toolClass: 'http', actions: ['get'], constraints: { allowedHosts: ['api.example.com'] } },
				{ toolClass: 'file', actions: ['read'], constraints: { allowedPaths: ['./data/**'] } },
				{ toolClass: 'shell', actions: ['exec'] },
			],
		},
		policies: [
			{ id: 'allow-http-get', name: 'Allow GET', priority: 100,
				match: { toolClass: 'http' as const, action: 'get' }, decision: 'allow' as const, reason: 'Allowed' },
			{ id: 'allow-file-read', name: 'Allow reads', priority: 100,
				match: { toolClass: 'file' as const, action: 'read' }, decision: 'allow' as const, reason: 'Allowed' },
			{ id: 'approve-shell', name: 'Shell needs approval', priority: 50,
				match: { toolClass: 'shell' as const }, decision: 'require-approval' as const, reason: 'Needs approval' },
		],
		auditLog: auditDb,
		runStatePolicy: { maxDeniedSensitiveActions: 10, behavioralRules: true },
	});

	// Create protected tool map — works with any model
	const tools = protectTools(firewall, {
		web_search: { toolClass: 'http', action: 'get' },
		read_file:  { toolClass: 'file', action: 'read' },
		run_shell:  { toolClass: 'shell', action: 'exec' },
	});

	console.log(`\n${CYAN}${BOLD}${'═'.repeat(60)}${RESET}`);
	console.log(`${CYAN}${BOLD}  Custom Agent Loop — AriKernel Demo${RESET}`);
	console.log(`${CYAN}${BOLD}${'═'.repeat(60)}${RESET}`);
	console.log(`${DIM}  This works with any model: OpenAI, Claude, Gemini, etc.${RESET}`);
	console.log(`${DIM}  AriKernel protects tool execution, not the model.${RESET}\n`);

	// Simulate the agent loop: model picks tools, AriKernel enforces
	for (let i = 0; i < MODEL_TOOL_CALLS.length; i++) {
		const call = MODEL_TOOL_CALLS[i];
		console.log(`${YELLOW}${BOLD}Step ${i + 1}${RESET} ${BOLD}${call.description}${RESET}`);
		console.log(`${DIM}  model selects: ${call.tool}(${JSON.stringify(call.args)})${RESET}`);

		try {
			const toolFn = tools[call.tool];
			if (!toolFn) throw new Error(`Unknown tool: ${call.tool}`);
			await toolFn(call.args);
			console.log(`  ${GREEN}${BOLD}ALLOWED${RESET}\n`);
		} catch (err: any) {
			console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}— ${err.message}${RESET}\n`);
		}
	}

	// Summary
	const events = firewall.getEvents();
	const allowed = events.filter((e) => e.decision.verdict === 'allow').length;
	const denied = events.filter((e) => e.decision.verdict === 'deny' && e.toolCall.toolClass !== '_system').length;

	console.log(`${CYAN}${BOLD}${'═'.repeat(60)}${RESET}`);
	console.log(`  ${GREEN}${allowed} allowed${RESET}  ${RED}${denied} denied${RESET}\n`);

	firewall.close();

	console.log(`${CYAN}${BOLD}Forensic follow-up:${RESET}`);
	console.log(`  arikernel trace --latest --db ${auditDb}`);
	console.log(`  arikernel replay --latest --step --db ${auditDb}\n`);
}

runAgentLoop().catch(console.error);
