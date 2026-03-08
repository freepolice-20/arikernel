/**
 * demo-mcp.ts
 *
 * Demonstrates AriKernel MCP integration: protectMCPTools() wraps a set of
 * MCP tools and routes every callTool() through the full enforcement pipeline.
 *
 * Run:
 *   npx pnpm --filter @arikernel/runtime build
 *   npx pnpm --filter @arikernel/mcp-adapter build
 *   npx tsx examples/demo-mcp.ts
 */

import { createFirewall } from '@arikernel/runtime';
import { protectMCPTools } from '@arikernel/mcp-adapter';
import type { MCPTool } from '@arikernel/mcp-adapter';
import { replayRun } from '@arikernel/audit-log';
import { AuditStore } from '@arikernel/audit-log';

const DB_PATH = './demo-mcp-audit.db';

// ── Define some mock MCP tools ────────────────────────────────────────────────

const webSearchTool: MCPTool = {
	name: 'web_search',
	description: 'Search the web',
	inputSchema: { type: 'object', properties: { query: { type: 'string' } } },
	async execute(args) {
		return { results: [`Result for: ${args['query']}`] };
	},
};

const ragLookupTool: MCPTool = {
	name: 'rag_lookup',
	description: 'Retrieve documents from a vector store',
	inputSchema: { type: 'object', properties: { source: { type: 'string' }, query: { type: 'string' } } },
	async execute(args) {
		return { documents: [`Doc from ${args['source']}: ${args['query']}`] };
	},
};

const sendEmailTool: MCPTool = {
	name: 'send_email',
	description: 'Send an email',
	inputSchema: { type: 'object', properties: { to: { type: 'string' }, body: { type: 'string' } } },
	async execute(args) {
		return { sent: true, to: args['to'] };
	},
};

// ── Bootstrap firewall ────────────────────────────────────────────────────────

const firewall = createFirewall({
	principal: {
		name: 'mcp-demo-agent',
		capabilities: [{ toolClass: 'mcp' }],
	},
	policies: './policies/safe-defaults.yaml',
	auditLog: DB_PATH,
});

// ── Protect MCP tools ─────────────────────────────────────────────────────────

const mcp = protectMCPTools(firewall, [webSearchTool, ragLookupTool, sendEmailTool]);

console.log('\n=== AriKernel MCP Adapter Demo ===\n');
console.log('Registered tools:', mcp.listTools().map((t) => t.name).join(', '));
console.log();

// ── Tool call 1: web_search — allowed, auto-tainted tool-output ───────────────
try {
	console.log('1. callTool("web_search", { query: "AI safety" })');
	const r1 = await mcp.callTool('web_search', { query: 'AI safety' });
	console.log('   ✓ Result:', JSON.stringify(r1));
} catch (e) {
	console.log('   ✗ Error:', (e as Error).message);
}

// ── Tool call 2: rag_lookup — allowed, auto-tainted rag:<source> ──────────────
try {
	console.log('2. callTool("rag_lookup", { source: "internal-docs", query: "policy" })');
	const r2 = await mcp.callTool('rag_lookup', { source: 'internal-docs', query: 'policy' });
	console.log('   ✓ Result:', JSON.stringify(r2));
} catch (e) {
	console.log('   ✗ Error:', (e as Error).message);
}

// ── Tool call 3: url-bearing arg — auto-tainted web:<hostname> ────────────────
try {
	console.log('3. callTool("web_search", { query: "test", url: "https://example.com/data" })');
	const r3 = await mcp.callTool('web_search', { query: 'test', url: 'https://example.com/data' });
	console.log('   ✓ Result:', JSON.stringify(r3));
} catch (e) {
	console.log('   ✗ Error:', (e as Error).message);
}

// ── Tool call 4: unknown tool — denied ───────────────────────────────────────
try {
	console.log('4. callTool("nonexistent_tool", {})');
	await mcp.callTool('nonexistent_tool', {});
	console.log('   ✓ Result (unexpected success)');
} catch (e) {
	console.log('   ✗ Denied (expected):', (e as Error).message);
}

// ── Replay audit log ──────────────────────────────────────────────────────────
firewall.close();

console.log('\n=== Audit Replay ===\n');
const store = new AuditStore(DB_PATH);
const replay = replayRun(store, firewall.runId);
store.close();

if (!replay) {
	console.log('No replay found.');
} else {
	console.log(`Run ID: ${replay.runContext.runId}`);
	console.log(`Hash chain: ${replay.integrity.valid ? 'VALID' : 'INVALID'}`);
	console.log(`Events: ${replay.events.length}`);
	console.log();
	for (const ev of replay.events) {
		const tc = ev.toolCall;
		const taints = tc.taintLabels.map((t) => `${t.source}:${t.origin}`).join(', ');
		const taintStr = taints ? ` [taint: ${taints}]` : '';
		const resultTaints = (ev.result?.taintLabels ?? []).map((t) => `${t.source}:${t.origin}`).join(', ');
		const resultTaintStr = resultTaints ? ` → result[taint: ${resultTaints}]` : '';
		console.log(`  #${tc.sequence} ${ev.decision.verdict.toUpperCase()} ${tc.toolClass}.${tc.action}${taintStr}${resultTaintStr}`);
	}
}

console.log('\nDone.\n');
