import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SidecarServer, SidecarClient } from '../src/index.js';

// ── helpers ───────────────────────────────────────────────────────────────────

function tempDir(): string {
	return mkdtempSync(join(tmpdir(), 'arikernel-sidecar-test-'));
}

const ALLOW_HTTP_POLICY = [
	{
		id: 'allow-http',
		name: 'Allow HTTP',
		priority: 10,
		match: { toolClass: 'http' },
		decision: 'allow' as const,
		reason: 'HTTP allowed in tests',
	},
];

const DENY_ALL_POLICY = [
	{
		id: 'deny-all',
		name: 'Deny All',
		priority: 1,
		match: {},
		decision: 'deny' as const,
		reason: 'Deny all in tests',
	},
];

// ── server lifecycle ──────────────────────────────────────────────────────────

describe('SidecarServer lifecycle', () => {
	let server: SidecarServer;
	let dir: string;

	beforeEach(async () => {
		dir = tempDir();
		server = new SidecarServer({
			port: 18787,
			policy: ALLOW_HTTP_POLICY,
			auditLog: join(dir, 'audit.db'),
		});
		await server.listen();
	});

	afterEach(async () => {
		await server.close();
		rmSync(dir, { recursive: true, force: true });
	});

	it('GET /health returns 200', async () => {
		const res = await fetch('http://localhost:18787/health');
		expect(res.status).toBe(200);
		const body = await res.json() as { status: string };
		expect(body.status).toBe('ok');
	});

	it('unknown route returns 404', async () => {
		const res = await fetch('http://localhost:18787/unknown');
		expect(res.status).toBe(404);
	});
});

// ── execute endpoint ──────────────────────────────────────────────────────────

describe('POST /execute — validation', () => {
	let server: SidecarServer;
	let dir: string;

	beforeEach(async () => {
		dir = tempDir();
		server = new SidecarServer({
			port: 18788,
			policy: ALLOW_HTTP_POLICY,
			auditLog: join(dir, 'audit.db'),
		});
		await server.listen();
	});

	afterEach(async () => {
		await server.close();
		rmSync(dir, { recursive: true, force: true });
	});

	it('rejects missing principalId', async () => {
		const res = await fetch('http://localhost:18788/execute', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ toolClass: 'http', action: 'GET', params: {} }),
		});
		expect(res.status).toBe(400);
		const body = await res.json() as { allowed: boolean; error: string };
		expect(body.allowed).toBe(false);
		expect(body.error).toContain('principalId');
	});

	it('rejects invalid toolClass', async () => {
		const res = await fetch('http://localhost:18788/execute', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ principalId: 'agent-1', toolClass: 'invalid', action: 'GET', params: {} }),
		});
		expect(res.status).toBe(400);
		const body = await res.json() as { allowed: boolean };
		expect(body.allowed).toBe(false);
	});

	it('rejects non-object params', async () => {
		const res = await fetch('http://localhost:18788/execute', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ principalId: 'agent-1', toolClass: 'http', action: 'GET', params: 'bad' }),
		});
		expect(res.status).toBe(400);
		const body = await res.json() as { allowed: boolean };
		expect(body.allowed).toBe(false);
	});

	it('rejects invalid JSON body', async () => {
		const res = await fetch('http://localhost:18788/execute', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: 'not-json',
		});
		expect(res.status).toBe(400);
	});
});

// ── policy enforcement ────────────────────────────────────────────────────────

describe('POST /execute — policy enforcement', () => {
	let server: SidecarServer;
	let dir: string;

	beforeEach(async () => {
		dir = tempDir();
		server = new SidecarServer({
			port: 18789,
			policy: DENY_ALL_POLICY,
			auditLog: join(dir, 'audit.db'),
		});
		await server.listen();
	});

	afterEach(async () => {
		await server.close();
		rmSync(dir, { recursive: true, force: true });
	});

	it('deny-all policy returns 403 with allowed=false', async () => {
		const res = await fetch('http://localhost:18789/execute', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ principalId: 'agent-1', toolClass: 'http', action: 'GET', params: { url: 'http://example.com' } }),
		});
		expect(res.status).toBe(403);
		const body = await res.json() as { allowed: boolean };
		expect(body.allowed).toBe(false);
	});
});

// ── SidecarClient ─────────────────────────────────────────────────────────────

describe('SidecarClient', () => {
	let server: SidecarServer;
	let client: SidecarClient;
	let dir: string;

	beforeEach(async () => {
		dir = tempDir();
		server = new SidecarServer({
			port: 18790,
			policy: DENY_ALL_POLICY,
			auditLog: join(dir, 'audit.db'),
		});
		await server.listen();
		client = new SidecarClient({ baseUrl: 'http://localhost:18790', principalId: 'test-agent' });
	});

	afterEach(async () => {
		await server.close();
		rmSync(dir, { recursive: true, force: true });
	});

	it('health() returns true when server is up', async () => {
		expect(await client.health()).toBe(true);
	});

	it('execute() returns allowed=false under deny-all policy', async () => {
		const result = await client.execute('file', 'read', { path: '/etc/passwd' });
		expect(result.allowed).toBe(false);
		expect(result.error).toBeTruthy();
	});

	it('callId is present in response', async () => {
		const result = await client.execute('shell', 'exec', { command: 'echo hi' });
		expect(result.callId).toBeTruthy();
	});
});

// ── per-principal isolation ───────────────────────────────────────────────────

describe('per-principal isolation', () => {
	let server: SidecarServer;
	let dir: string;

	beforeEach(async () => {
		dir = tempDir();
		server = new SidecarServer({
			port: 18791,
			policy: DENY_ALL_POLICY,
			auditLog: join(dir, 'audit.db'),
		});
		await server.listen();
	});

	afterEach(async () => {
		await server.close();
		rmSync(dir, { recursive: true, force: true });
	});

	it('two principals get independent firewall instances', async () => {
		const post = (principalId: string) =>
			fetch('http://localhost:18791/execute', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ principalId, toolClass: 'file', action: 'read', params: { path: '/tmp/x' } }),
			}).then((r) => r.json());

		const [r1, r2] = await Promise.all([post('agent-A'), post('agent-B')]);
		// Both denied (deny-all) but each has its own callId prefix
		expect((r1 as { allowed: boolean }).allowed).toBe(false);
		expect((r2 as { allowed: boolean }).allowed).toBe(false);
		// callIds should differ
		expect((r1 as { callId?: string }).callId).not.toBe((r2 as { callId?: string }).callId);
	});
});
