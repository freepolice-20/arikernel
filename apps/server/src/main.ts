import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { resolve } from 'node:path';
import { ToolCallDeniedError } from '@agent-firewall/core';
import { SessionManager, type SessionConfig } from './sessions.js';

const PORT = Number(process.env.PORT ?? 9099);
const POLICY = process.env.POLICY ?? resolve('policies', 'safe-defaults.yaml');
const AUDIT_DB = process.env.AUDIT_DB ?? resolve('audit.db');

const sessions = new SessionManager(POLICY, AUDIT_DB);

function json(res: ServerResponse, status: number, body: unknown): void {
	res.writeHead(status, { 'Content-Type': 'application/json' });
	res.end(JSON.stringify(body));
}

async function readBody(req: IncomingMessage): Promise<unknown> {
	const chunks: Buffer[] = [];
	for await (const chunk of req) chunks.push(chunk as Buffer);
	return JSON.parse(Buffer.concat(chunks).toString());
}

function parseRoute(url: string): { path: string; sessionId?: string; action?: string } {
	const parts = url.split('/').filter(Boolean);
	if (parts[0] !== 'session') return { path: url };
	if (parts.length === 1) return { path: '/session' };
	if (parts.length === 2) return { path: '/session/:id', sessionId: parts[1] };
	return { path: '/session/:id/:action', sessionId: parts[1], action: parts[2] };
}

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
	const method = req.method ?? 'GET';
	const route = parseRoute(req.url ?? '/');

	// POST /session — create session
	if (method === 'POST' && route.path === '/session') {
		const body = (await readBody(req)) as SessionConfig;
		if (!body.principal || !body.capabilities) {
			json(res, 400, { error: 'Missing principal or capabilities' });
			return;
		}
		const result = sessions.create(body);
		json(res, 201, result);
		return;
	}

	// POST /session/:id/capability — request capability
	if (method === 'POST' && route.action === 'capability' && route.sessionId) {
		const firewall = sessions.get(route.sessionId);
		if (!firewall) { json(res, 404, { error: 'Session not found' }); return; }
		const body = (await readBody(req)) as {
			capabilityClass: string;
			taintLabels?: Array<{ source: string; origin: string; confidence?: number }>;
		};
		const decision = firewall.requestCapability(body.capabilityClass as any, {
			taintLabels: body.taintLabels?.map((t) => ({
				source: t.source as any,
				origin: t.origin,
				confidence: t.confidence ?? 1.0,
				addedAt: new Date().toISOString(),
			})),
		});
		json(res, 200, {
			granted: decision.granted,
			grantId: decision.grant?.id ?? null,
			reason: decision.reason,
			expiresAt: decision.grant?.lease.expiresAt ?? null,
			maxCalls: decision.grant?.lease.maxCalls ?? null,
			constraints: decision.grant?.constraints ?? null,
		});
		return;
	}

	// POST /session/:id/execute — execute decision check
	if (method === 'POST' && route.action === 'execute' && route.sessionId) {
		const firewall = sessions.get(route.sessionId);
		if (!firewall) { json(res, 404, { error: 'Session not found' }); return; }
		const body = (await readBody(req)) as {
			toolClass: string;
			action: string;
			parameters: Record<string, unknown>;
			grantId?: string;
			taintLabels?: Array<{ source: string; origin: string; confidence?: number }>;
		};
		try {
			const result = await firewall.execute({
				toolClass: body.toolClass as any,
				action: body.action,
				parameters: body.parameters,
				...(body.grantId ? { grantId: body.grantId } : {}),
				taintLabels: body.taintLabels?.map((t) => ({
					source: t.source as any,
					origin: t.origin,
					confidence: t.confidence ?? 1.0,
					addedAt: new Date().toISOString(),
				})),
			});
			json(res, 200, {
				verdict: 'allow',
				success: result.success,
				data: result.data,
				durationMs: result.durationMs,
			});
		} catch (err) {
			// Use duck-typing to avoid instanceof issues with bundled code
			if (err instanceof Error && 'decision' in err && (err as any).decision?.verdict === 'deny') {
				const decision = (err as any).decision;
				json(res, 403, {
					verdict: 'deny',
					reason: decision.reason,
					rule: decision.matchedRule?.name ?? null,
				});
			} else {
				json(res, 500, { error: err instanceof Error ? err.message : String(err) });
			}
		}
		return;
	}

	// POST /session/:id/revoke — revoke a grant
	if (method === 'POST' && route.action === 'revoke' && route.sessionId) {
		const firewall = sessions.get(route.sessionId);
		if (!firewall) { json(res, 404, { error: 'Session not found' }); return; }
		const body = (await readBody(req)) as { grantId: string };
		const revoked = firewall.revokeGrant(body.grantId);
		json(res, 200, { revoked });
		return;
	}

	// DELETE /session/:id — close session
	if (method === 'DELETE' && route.path === '/session/:id' && route.sessionId) {
		const destroyed = sessions.destroy(route.sessionId);
		json(res, destroyed ? 200 : 404, { closed: destroyed });
		return;
	}

	// GET /health
	if (method === 'GET' && (req.url === '/health' || req.url === '/')) {
		json(res, 200, { status: 'ok', version: '0.1.0' });
		return;
	}

	json(res, 404, { error: 'Not found' });
}

const server = createServer(async (req, res) => {
	try {
		await handleRequest(req, res);
	} catch (err) {
		json(res, 500, { error: err instanceof Error ? err.message : 'Internal error' });
	}
});

server.listen(PORT, () => {
	console.log(`Agent Firewall server listening on http://localhost:${PORT}`);
	console.log(`  Policy: ${POLICY}`);
	console.log(`  Audit:  ${AUDIT_DB}`);
});

process.on('SIGTERM', () => { sessions.close(); server.close(); });
process.on('SIGINT', () => { sessions.close(); server.close(); });
