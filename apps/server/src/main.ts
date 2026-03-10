import { type IncomingMessage, type ServerResponse, createServer } from "node:http";
import { resolve } from "node:path";
import { ToolCallDeniedError } from "@arikernel/core";
import { type SessionConfig, SessionManager } from "./sessions.js";

/** Constant-time string comparison to prevent timing side-channels. */
function timingSafeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) {
		let result = a.length ^ b.length;
		for (let i = 0; i < a.length; i++) {
			result |= a.charCodeAt(i) ^ (b.charCodeAt(i % b.length) || 0);
		}
		return result === 0; // always false when lengths differ
	}
	let result = 0;
	for (let i = 0; i < a.length; i++) {
		result |= a.charCodeAt(i) ^ b.charCodeAt(i);
	}
	return result === 0;
}

const PORT = Number(process.env.PORT ?? 9099);
const HOST = process.env.HOST ?? "127.0.0.1";
const POLICY = process.env.POLICY ?? resolve("policies", "safe-defaults.yaml");
const AUDIT_DB = process.env.AUDIT_DB ?? resolve("audit.db");
const AUTH_TOKEN = process.env.AUTH_TOKEN;
const MAX_BODY_BYTES = Number(process.env.MAX_BODY_BYTES ?? 1_048_576); // 1 MB

/* ── Minimal per-IP rate limiter ─────────────────────────────────── */
const RATE_WINDOW_MS = 60_000;
const RATE_MAX = Number(process.env.RATE_MAX ?? 120); // requests per window
const hits = new Map<string, { count: number; resetAt: number }>();

function rateOk(ip: string): boolean {
	const now = Date.now();
	let entry = hits.get(ip);
	if (!entry || now >= entry.resetAt) {
		entry = { count: 1, resetAt: now + RATE_WINDOW_MS };
		hits.set(ip, entry);
		return true;
	}
	entry.count++;
	return entry.count <= RATE_MAX;
}

const sessions = new SessionManager(POLICY, AUDIT_DB);

function json(res: ServerResponse, status: number, body: unknown): void {
	res.writeHead(status, { "Content-Type": "application/json" });
	res.end(JSON.stringify(body));
}

async function readBody(req: IncomingMessage): Promise<unknown> {
	const chunks: Buffer[] = [];
	let size = 0;
	for await (const chunk of req) {
		size += (chunk as Buffer).length;
		if (size > MAX_BODY_BYTES) throw new BodyTooLargeError();
		chunks.push(chunk as Buffer);
	}
	try {
		return JSON.parse(Buffer.concat(chunks).toString());
	} catch {
		throw new JsonParseError();
	}
}

class BodyTooLargeError extends Error {
	constructor() {
		super("Request body exceeds size limit");
	}
}
class JsonParseError extends Error {
	constructor() {
		super("Invalid JSON in request body");
	}
}

function parseRoute(url: string): { path: string; sessionId?: string; action?: string } {
	const parts = url.split("/").filter(Boolean);
	if (parts[0] !== "session") return { path: url };
	if (parts.length === 1) return { path: "/session" };
	if (parts.length === 2) return { path: "/session/:id", sessionId: parts[1] };
	return { path: "/session/:id/:action", sessionId: parts[1], action: parts[2] };
}

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
	const method = req.method ?? "GET";
	const route = parseRoute(req.url ?? "/");

	// POST /session — create session
	if (method === "POST" && route.path === "/session") {
		const body = (await readBody(req)) as SessionConfig;
		if (!body.principal || !body.capabilities) {
			json(res, 400, { error: "Missing principal or capabilities" });
			return;
		}
		const result = sessions.create(body);
		json(res, 201, result);
		return;
	}

	// POST /session/:id/capability — request capability
	if (method === "POST" && route.action === "capability" && route.sessionId) {
		const firewall = sessions.get(route.sessionId);
		if (!firewall) {
			json(res, 404, { error: "Session not found" });
			return;
		}
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
	if (method === "POST" && route.action === "execute" && route.sessionId) {
		const firewall = sessions.get(route.sessionId);
		if (!firewall) {
			json(res, 404, { error: "Session not found" });
			return;
		}
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
				verdict: "allow",
				success: result.success,
				data: result.data,
				durationMs: result.durationMs,
			});
		} catch (err) {
			// Use duck-typing to avoid instanceof issues with bundled code
			if (err instanceof Error && "decision" in err && (err as any).decision?.verdict === "deny") {
				const decision = (err as any).decision;
				json(res, 403, {
					verdict: "deny",
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
	if (method === "POST" && route.action === "revoke" && route.sessionId) {
		const firewall = sessions.get(route.sessionId);
		if (!firewall) {
			json(res, 404, { error: "Session not found" });
			return;
		}
		const body = (await readBody(req)) as { grantId: string };
		const revoked = firewall.revokeGrant(body.grantId);
		json(res, 200, { revoked });
		return;
	}

	// DELETE /session/:id — close session
	if (method === "DELETE" && route.path === "/session/:id" && route.sessionId) {
		const destroyed = sessions.destroy(route.sessionId);
		json(res, destroyed ? 200 : 404, { closed: destroyed });
		return;
	}

	// GET /health
	if (method === "GET" && (req.url === "/health" || req.url === "/")) {
		json(res, 200, { status: "ok", version: "0.1.0" });
		return;
	}

	json(res, 404, { error: "Not found" });
}

const server = createServer(async (req, res) => {
	try {
		// Use X-Forwarded-For when behind a trusted proxy, fall back to socket address
		const forwarded = req.headers["x-forwarded-for"];
		const ip =
			(typeof forwarded === "string" ? forwarded.split(",")[0].trim() : undefined) ??
			req.socket.remoteAddress ??
			"unknown";

		// Rate limiting
		if (!rateOk(ip)) {
			json(res, 429, { error: "Too many requests" });
			return;
		}

		// Bearer auth (when AUTH_TOKEN is set)
		if (AUTH_TOKEN) {
			const authHeader = req.headers.authorization;
			if (!authHeader || !authHeader.startsWith("Bearer ")) {
				json(res, 401, { error: "Missing or malformed Authorization header" });
				return;
			}
			if (!timingSafeEqual(authHeader.slice(7), AUTH_TOKEN)) {
				json(res, 401, { error: "Unauthorized" });
				return;
			}
		}

		await handleRequest(req, res);
	} catch (err) {
		if (err instanceof BodyTooLargeError) {
			json(res, 413, { error: err.message });
		} else if (err instanceof JsonParseError) {
			json(res, 400, { error: err.message });
		} else {
			json(res, 500, { error: err instanceof Error ? err.message : "Internal error" });
		}
	}
});

server.listen(PORT, HOST, () => {
	console.log(`AriKernel server listening on http://${HOST}:${PORT}`);
	console.log(`  Policy:    ${POLICY}`);
	console.log(`  Audit:     ${AUDIT_DB}`);
	console.log(`  Auth:      ${AUTH_TOKEN ? "enabled" : "disabled (set AUTH_TOKEN to enable)"}`);
	console.log(`  Max body:  ${MAX_BODY_BYTES} bytes`);
	console.log(`  Rate cap:  ${RATE_MAX} req/${RATE_WINDOW_MS / 1000}s per IP`);
	if (HOST === "0.0.0.0") {
		console.warn("  ⚠ Server bound to all interfaces — ensure this is intentional");
	}
});

process.on("SIGTERM", () => {
	sessions.close();
	server.close();
});
process.on("SIGINT", () => {
	sessions.close();
	server.close();
});
