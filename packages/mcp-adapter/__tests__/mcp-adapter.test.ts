import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createFirewall } from '@arikernel/runtime';
import { protectMCPTools } from '../src/adapter.js';
import { McpDispatchExecutor } from '../src/executor.js';
import type { MCPTool } from '../src/types.js';

// ── helpers ───────────────────────────────────────────────────────────────────

function tempDb(): string {
	const dir = mkdtempSync(join(tmpdir(), 'arikernel-mcp-test-'));
	return join(dir, 'audit.db');
}

function makeFirewall(dbPath: string) {
	return createFirewall({
		principal: { name: 'test-agent', capabilities: [{ toolClass: 'mcp' }] },
		policies: [
			{
				id: 'allow-mcp',
				name: 'Allow MCP',
				priority: 10,
				match: { toolClass: 'mcp' },
				decision: 'allow',
				reason: 'MCP allowed in tests',
			},
		],
		auditLog: dbPath,
	});
}

const echoTool: MCPTool = {
	name: 'echo',
	description: 'Echo args back',
	async execute(args) {
		return args;
	},
};

const failTool: MCPTool = {
	name: 'fail',
	description: 'Always throws',
	async execute() {
		throw new Error('intentional failure');
	},
};

const urlTool: MCPTool = {
	name: 'fetch_url',
	description: 'Fetch a URL',
	async execute(args) {
		return { fetched: args['url'] };
	},
};

const ragTool: MCPTool = {
	name: 'rag_lookup',
	description: 'RAG lookup',
	async execute(args) {
		return { docs: [`from ${args['source']}`] };
	},
};

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('protectMCPTools', () => {
	let dbPath: string;

	beforeEach(() => {
		dbPath = tempDb();
	});

	afterEach(() => {
		try {
			rmSync(dbPath);
		} catch {
			/* ignore */
		}
	});

	it('allows a registered MCP tool call and returns data', async () => {
		const fw = makeFirewall(dbPath);
		const mcp = protectMCPTools(fw, [echoTool]);
		const result = await mcp.callTool('echo', { hello: 'world' });
		expect(result).toEqual({ hello: 'world' });
		fw.close();
	});

	it('throws when an unknown tool is called', async () => {
		const fw = makeFirewall(dbPath);
		const mcp = protectMCPTools(fw, [echoTool]);
		await expect(mcp.callTool('nonexistent', {})).rejects.toThrow("Unknown MCP tool: 'nonexistent'");
		fw.close();
	});

	it('propagates tool errors as thrown exceptions', async () => {
		const fw = makeFirewall(dbPath);
		const mcp = protectMCPTools(fw, [failTool]);
		await expect(mcp.callTool('fail', {})).rejects.toThrow('intentional failure');
		fw.close();
	});

	it('listTools returns metadata without execute', () => {
		const fw = makeFirewall(dbPath);
		const mcp = protectMCPTools(fw, [echoTool, urlTool]);
		const listed = mcp.listTools();
		expect(listed).toHaveLength(2);
		expect(listed[0]).not.toHaveProperty('execute');
		expect(listed.map((t) => t.name)).toContain('echo');
		expect(listed.map((t) => t.name)).toContain('fetch_url');
		fw.close();
	});

	it('auto-taints url args with web:<hostname>', async () => {
		const fw = makeFirewall(dbPath);
		const mcp = protectMCPTools(fw, [urlTool]);
		await mcp.callTool('fetch_url', { url: 'https://example.com/api' });

		const events = fw.getEvents();
		const toolEvent = events.find((e) => e.toolCall.action === 'fetch_url');
		expect(toolEvent).toBeDefined();
		// Auto-taints are on the result, not the input toolCall
		const taints = (toolEvent!.result?.taintLabels ?? []) as Array<{ source: string; origin: string }>;
		expect(taints.some((t) => t.source === 'web' && t.origin === 'example.com')).toBe(true);
		fw.close();
	});

	it('auto-taints source args with rag:<source>', async () => {
		const fw = makeFirewall(dbPath);
		const mcp = protectMCPTools(fw, [ragTool]);
		await mcp.callTool('rag_lookup', { source: 'my-corpus', query: 'test' });

		const events = fw.getEvents();
		const toolEvent = events.find((e) => e.toolCall.action === 'rag_lookup');
		expect(toolEvent).toBeDefined();
		const taints = (toolEvent!.result?.taintLabels ?? []) as Array<{ source: string; origin: string }>;
		expect(taints.some((t) => t.source === 'rag' && t.origin === 'my-corpus')).toBe(true);
		fw.close();
	});

	it('falls back to tool-output taint when no url/source args present', async () => {
		const fw = makeFirewall(dbPath);
		const mcp = protectMCPTools(fw, [echoTool]);
		await mcp.callTool('echo', { message: 'hello' });

		const events = fw.getEvents();
		const toolEvent = events.find((e) => e.toolCall.action === 'echo');
		expect(toolEvent).toBeDefined();
		const taints = (toolEvent!.result?.taintLabels ?? []) as Array<{ source: string }>;
		expect(taints.some((t) => t.source === 'tool-output')).toBe(true);
		fw.close();
	});

	it('records all tool calls in the audit log', async () => {
		const fw = makeFirewall(dbPath);
		const mcp = protectMCPTools(fw, [echoTool, urlTool]);

		await mcp.callTool('echo', { x: 1 });
		await mcp.callTool('fetch_url', { url: 'https://test.com' });

		const events = fw.getEvents().filter((e) => e.toolCall.toolClass === 'mcp');
		expect(events).toHaveLength(2);
		fw.close();
	});

	it('denies tool calls when policy denies mcp', async () => {
		const fw = createFirewall({
			principal: { name: 'restricted-agent', capabilities: [] },
			policies: [
				{
					id: 'deny-mcp',
					name: 'Deny MCP',
					priority: 10,
					match: { toolClass: 'mcp' },
					decision: 'deny',
					reason: 'MCP is not permitted',
				},
			],
			auditLog: dbPath,
		});
		const mcp = protectMCPTools(fw, [echoTool]);
		await expect(mcp.callTool('echo', {})).rejects.toThrow();
		fw.close();
	});
});

describe('McpDispatchExecutor', () => {
	it('returns error result for unknown tool', async () => {
		const executor = new McpDispatchExecutor();
		executor.register(echoTool);

		const result = await executor.execute({
			id: 'test-id',
			runId: 'run-1',
			sequence: 0,
			timestamp: new Date().toISOString(),
			principalId: 'p-1',
			toolClass: 'mcp',
			action: 'ghost',
			parameters: {},
			taintLabels: [],
		});

		expect(result.success).toBe(false);
		expect(result.error).toContain("Unknown MCP tool: 'ghost'");
	});
});
