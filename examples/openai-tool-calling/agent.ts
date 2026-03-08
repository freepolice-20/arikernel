/**
 * OpenAI Tool-Calling Agent — AriKernel Integration Example
 *
 * Demonstrates how AriKernel sits between an OpenAI-style model's tool calls
 * and actual tool execution. Every tool call goes through capability checks,
 * taint tracking, policy evaluation, and audit logging.
 *
 * Run:
 *   npx tsx examples/openai-tool-calling/agent.ts
 *   arikernel trace --latest
 *   arikernel replay --latest --step
 */

import { ToolCallDeniedError } from '@arikernel/core';
import type { TaintLabel, ToolCallRequest } from '@arikernel/core';
import { createFirewall } from '@arikernel/runtime';
import { resolve } from 'node:path';

// ── Inline protectOpenAITools (same pattern as @arikernel/adapters/openai) ──

interface ToolMapping {
	toolClass: string;
	action: string;
	taintLabels?: TaintLabel[];
}

function protectOpenAITools(
	firewall: ReturnType<typeof createFirewall>,
	mappings: Record<string, ToolMapping>,
) {
	const tools = new Map<string, (args: Record<string, unknown>) => Promise<any>>();

	for (const [name, mapping] of Object.entries(mappings)) {
		tools.set(name, async (parameters: Record<string, unknown>) => {
			const capClass = mapping.toolClass === 'shell' ? 'shell.exec'
				: `${mapping.toolClass}.${['get', 'read', 'query', 'list'].includes(mapping.action) ? 'read' : 'write'}`;
			const grant = firewall.requestCapability(capClass as any);
			if (!grant.granted) throw new Error(grant.reason ?? 'Capability denied');
			return firewall.execute({
				toolClass: mapping.toolClass as ToolCallRequest['toolClass'],
				action: mapping.action,
				parameters,
				grantId: grant.grant!.id,
				taintLabels: mapping.taintLabels,
			});
		});
	}

	return {
		async execute(toolName: string, args: Record<string, unknown>) {
			const fn = tools.get(toolName);
			if (!fn) throw new Error(`Unknown tool "${toolName}"`);
			return fn(args);
		},
		get toolNames() { return [...tools.keys()]; },
	};
}

// ── Colors ──────────────────────────────────────────────────────────

const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const MAGENTA = '\x1b[35m';
const RESET = '\x1b[0m';

// ── Agent scenario ──────────────────────────────────────────────────

async function runAgent() {
	const auditDb = resolve('arikernel-audit.db');

	const firewall = createFirewall({
		principal: {
			name: 'openai-assistant',
			capabilities: [
				{ toolClass: 'http', actions: ['get'], constraints: { allowedHosts: ['api.example.com'] } },
				{ toolClass: 'file', actions: ['read'], constraints: { allowedPaths: ['./data/**'] } },
				{ toolClass: 'shell', actions: ['exec'] },
			],
		},
		policies: [
			{ id: 'allow-http-get', name: 'Allow HTTP GET', priority: 100,
				match: { toolClass: 'http' as const, action: 'get' }, decision: 'allow' as const, reason: 'HTTP GET allowed' },
			{ id: 'allow-file-read', name: 'Allow file reads', priority: 100,
				match: { toolClass: 'file' as const, action: 'read' }, decision: 'allow' as const, reason: 'File reads allowed' },
			{ id: 'deny-tainted-shell', name: 'Deny tainted shell', priority: 10,
				match: { toolClass: 'shell' as const, taintSources: ['web', 'rag', 'email'] },
				decision: 'deny' as const, reason: 'Shell with untrusted input forbidden' },
		],
		auditLog: auditDb,
		runStatePolicy: { maxDeniedSensitiveActions: 10, behavioralRules: true },
	});

	// Map OpenAI tool names to AriKernel tool classes
	const tools = protectOpenAITools(firewall, {
		web_search:  { toolClass: 'http', action: 'get' },
		read_file:   { toolClass: 'file', action: 'read' },
		run_command: { toolClass: 'shell', action: 'exec' },
	});

	console.log(`\n${CYAN}${BOLD}${'═'.repeat(60)}${RESET}`);
	console.log(`${CYAN}${BOLD}  OpenAI Tool-Calling Agent — AriKernel Demo${RESET}`);
	console.log(`${CYAN}${BOLD}${'═'.repeat(60)}${RESET}`);
	console.log(`${DIM}  Run ID: ${firewall.runId}${RESET}`);
	console.log(`${DIM}  Tools:  ${tools.toolNames.join(', ')}${RESET}\n`);

	// Simulate OpenAI model requesting tool calls

	// Step 1: Model calls web_search (allowed)
	console.log(`${YELLOW}${BOLD}Step 1${RESET} ${BOLD}Model calls web_search${RESET}`);
	console.log(`${DIM}  tool_call: web_search({ url: "https://api.example.com/data" })${RESET}`);
	try {
		await tools.execute('web_search', { url: 'https://api.example.com/data' });
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET}\n`);
	} catch (err: any) {
		console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}— ${err.message}${RESET}\n`);
	}

	// Step 2: Model calls read_file on allowed path (allowed)
	console.log(`${YELLOW}${BOLD}Step 2${RESET} ${BOLD}Model calls read_file on safe path${RESET}`);
	console.log(`${DIM}  tool_call: read_file({ path: "./data/report.csv" })${RESET}`);
	try {
		await tools.execute('read_file', { path: './data/report.csv' });
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET}\n`);
	} catch (err: any) {
		console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}— ${err.message}${RESET}\n`);
	}

	// Step 3: Model calls read_file on sensitive path (blocked by constraints)
	console.log(`${YELLOW}${BOLD}Step 3${RESET} ${BOLD}Model calls read_file on ~/.ssh/id_rsa${RESET}`);
	console.log(`${DIM}  tool_call: read_file({ path: "~/.ssh/id_rsa" })${RESET}`);
	try {
		await tools.execute('read_file', { path: '~/.ssh/id_rsa' });
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET}\n`);
	} catch (err: any) {
		console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}— ${err.message}${RESET}\n`);
	}

	// Summary
	const events = firewall.getEvents();
	const allowed = events.filter((e) => e.decision.verdict === 'allow').length;
	const denied = events.filter((e) => e.decision.verdict === 'deny' && e.toolCall.toolClass !== '_system').length;

	console.log(`${CYAN}${BOLD}${'═'.repeat(60)}${RESET}`);
	console.log(`${CYAN}${BOLD}  Results${RESET}`);
	console.log(`${CYAN}${BOLD}${'═'.repeat(60)}${RESET}`);
	console.log(`  ${GREEN}${allowed} allowed${RESET}  ${RED}${denied} denied${RESET}`);
	console.log(`  ${DIM}Restricted: ${firewall.isRestricted}${RESET}\n`);

	firewall.close();

	console.log(`${CYAN}${BOLD}Forensic follow-up:${RESET}`);
	console.log(`  arikernel trace --latest --db ${auditDb}`);
	console.log(`  arikernel replay --latest --step --db ${auditDb}\n`);
}

runAgent().catch(console.error);
