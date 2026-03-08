/**
 * CrewAI Tool Protection — AriKernel Integration Example
 *
 * Demonstrates how to protect CrewAI-style tool execution with AriKernel.
 * In a real setup, CrewAI tools are Python-based — this example shows the
 * pattern for routing tool calls through AriKernel's enforcement pipeline.
 *
 * Run:
 *   npx tsx examples/crewai-tool-protection/agent.ts
 *   arikernel trace --latest
 *   arikernel replay --latest --step
 */

import { ToolCallDeniedError } from '@arikernel/core';
import type { TaintLabel, ToolCallRequest } from '@arikernel/core';
import { createFirewall } from '@arikernel/runtime';
import { resolve } from 'node:path';

// ── Inline CrewAI adapter (same pattern as @arikernel/adapters/crewai) ──

function createCrewAIAdapter(firewall: ReturnType<typeof createFirewall>) {
	const tools = new Map<string, (args: Record<string, unknown>) => Promise<any>>();

	return {
		register(name: string, toolClass: string, action: string) {
			tools.set(name, async (parameters: Record<string, unknown>) => {
				const isRead = ['get', 'read', 'query', 'list'].includes(action);
				const capClass = `${toolClass}.${isRead ? 'read' : 'write'}`;
				const grant = firewall.requestCapability(capClass as any);
				if (!grant.granted) throw new Error(grant.reason ?? 'Capability denied');
				return firewall.execute({
					toolClass: toolClass as ToolCallRequest['toolClass'],
					action, parameters,
					grantId: grant.grant!.id,
				});
			});
			return this;
		},
		async execute(name: string, args: Record<string, unknown>) {
			const fn = tools.get(name);
			if (!fn) throw new Error(`Unknown tool "${name}"`);
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
const RESET = '\x1b[0m';

// ── Agent scenario ──────────────────────────────────────────────────

async function runAgent() {
	const auditDb = resolve('arikernel-audit.db');

	const firewall = createFirewall({
		principal: {
			name: 'crewai-research-crew',
			capabilities: [
				{ toolClass: 'http', actions: ['get'], constraints: { allowedHosts: ['api.example.com'] } },
				{ toolClass: 'file', actions: ['read', 'write'], constraints: { allowedPaths: ['./output/**'] } },
				{ toolClass: 'database', actions: ['query'] },
			],
		},
		policies: [
			{ id: 'allow-http-get', name: 'Allow HTTP GET', priority: 100,
				match: { toolClass: 'http' as const, action: 'get' }, decision: 'allow' as const, reason: 'HTTP GET allowed' },
			{ id: 'allow-file-read', name: 'Allow file reads', priority: 100,
				match: { toolClass: 'file' as const, action: 'read' }, decision: 'allow' as const, reason: 'File reads allowed' },
			{ id: 'allow-db-query', name: 'Allow DB queries', priority: 100,
				match: { toolClass: 'database' as const, action: 'query' }, decision: 'allow' as const, reason: 'DB queries allowed' },
			{ id: 'deny-file-write', name: 'Require approval for writes', priority: 50,
				match: { toolClass: 'file' as const, action: 'write' },
				decision: 'require-approval' as const, reason: 'File writes need approval' },
		],
		auditLog: auditDb,
		runStatePolicy: { maxDeniedSensitiveActions: 10, behavioralRules: true },
	});

	// Register CrewAI tools with AriKernel
	const adapter = createCrewAIAdapter(firewall);
	adapter
		.register('search_tool', 'http', 'get')
		.register('file_reader', 'file', 'read')
		.register('file_writer', 'file', 'write')
		.register('db_query', 'database', 'query');

	console.log(`\n${CYAN}${BOLD}${'═'.repeat(60)}${RESET}`);
	console.log(`${CYAN}${BOLD}  CrewAI Tool Protection — AriKernel Demo${RESET}`);
	console.log(`${CYAN}${BOLD}${'═'.repeat(60)}${RESET}`);
	console.log(`${DIM}  Run ID: ${firewall.runId}${RESET}`);
	console.log(`${DIM}  Tools:  ${adapter.toolNames.join(', ')}${RESET}\n`);

	// Step 1: Research agent searches the web (allowed)
	console.log(`${YELLOW}${BOLD}Step 1${RESET} ${BOLD}Research agent uses search_tool${RESET}`);
	try {
		await adapter.execute('search_tool', { url: 'https://api.example.com/papers' });
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET}\n`);
	} catch (err: any) {
		console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}— ${err.message}${RESET}\n`);
	}

	// Step 2: Analyst agent reads a file (allowed)
	console.log(`${YELLOW}${BOLD}Step 2${RESET} ${BOLD}Analyst agent reads output file${RESET}`);
	try {
		await adapter.execute('file_reader', { path: './output/analysis.json' });
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET}\n`);
	} catch (err: any) {
		console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}— ${err.message}${RESET}\n`);
	}

	// Step 3: Writer agent tries to write (requires approval — blocked)
	console.log(`${YELLOW}${BOLD}Step 3${RESET} ${BOLD}Writer agent tries file_writer${RESET}`);
	try {
		await adapter.execute('file_writer', { path: './output/report.md', content: '# Report' });
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET}\n`);
	} catch (err: any) {
		console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}— ${err.message}${RESET}\n`);
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

runAgent().catch(console.error);
