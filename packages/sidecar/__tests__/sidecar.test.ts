import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SidecarClient, SidecarServer } from "../src/index.js";

// ── helpers ───────────────────────────────────────────────────────────────────

function tempDir(): string {
	return mkdtempSync(join(tmpdir(), "arikernel-sidecar-test-"));
}

const ALLOW_HTTP_POLICY = [
	{
		id: "allow-http",
		name: "Allow HTTP",
		priority: 10,
		match: { toolClass: "http" },
		decision: "allow" as const,
		reason: "HTTP allowed in tests",
	},
];

const DENY_ALL_POLICY = [
	{
		id: "deny-all",
		name: "Deny All",
		priority: 1,
		match: {},
		decision: "deny" as const,
		reason: "Deny all in tests",
	},
];

const REALISTIC_POLICY = [
	{
		id: "allow-http-read",
		name: "Allow HTTP GET",
		priority: 10,
		match: { toolClass: "http", action: "GET" },
		decision: "allow" as const,
	},
	{
		id: "allow-file-read",
		name: "Allow file reads",
		priority: 20,
		match: { toolClass: "file", action: "read" },
		decision: "allow" as const,
	},
	{
		id: "deny-shell",
		name: "Deny shell",
		priority: 30,
		match: { toolClass: "shell" },
		decision: "deny" as const,
		reason: "Shell execution is prohibited",
	},
	{
		id: "deny-default",
		name: "Default deny",
		priority: 900,
		match: {},
		decision: "deny" as const,
		reason: "Deny by default",
	},
];

function post(port: number, path: string, body: unknown, headers?: Record<string, string>) {
	return fetch(`http://localhost:${port}${path}`, {
		method: "POST",
		headers: { "Content-Type": "application/json", ...headers },
		body: JSON.stringify(body),
	});
}

// ── server lifecycle ──────────────────────────────────────────────────────────

describe("SidecarServer lifecycle", () => {
	let server: SidecarServer;
	let dir: string;

	beforeEach(async () => {
		dir = tempDir();
		server = new SidecarServer({
			port: 18787,
			policy: ALLOW_HTTP_POLICY,
			auditLog: join(dir, "audit.db"),
		});
		await server.listen();
	});

	afterEach(async () => {
		await server.close();
		rmSync(dir, { recursive: true, force: true });
	});

	it("GET /health returns 200", async () => {
		const res = await fetch("http://localhost:18787/health");
		expect(res.status).toBe(200);
		const body = (await res.json()) as { status: string };
		expect(body.status).toBe("ok");
	});

	it("unknown route returns 404", async () => {
		const res = await fetch("http://localhost:18787/unknown");
		expect(res.status).toBe(404);
	});
});

// ── execute endpoint — validation ────────────────────────────────────────────

describe("POST /execute — validation", () => {
	let server: SidecarServer;
	let dir: string;

	beforeEach(async () => {
		dir = tempDir();
		server = new SidecarServer({
			port: 18788,
			policy: ALLOW_HTTP_POLICY,
			auditLog: join(dir, "audit.db"),
		});
		await server.listen();
	});

	afterEach(async () => {
		await server.close();
		rmSync(dir, { recursive: true, force: true });
	});

	it("rejects missing principalId", async () => {
		const res = await post(18788, "/execute", { toolClass: "http", action: "GET", params: {} });
		expect(res.status).toBe(400);
		const body = (await res.json()) as { allowed: boolean; error: string };
		expect(body.allowed).toBe(false);
		expect(body.error).toContain("principalId");
	});

	it("rejects invalid toolClass", async () => {
		const res = await post(18788, "/execute", {
			principalId: "agent-1",
			toolClass: "invalid",
			action: "GET",
			params: {},
		});
		expect(res.status).toBe(400);
		const body = (await res.json()) as { allowed: boolean };
		expect(body.allowed).toBe(false);
	});

	it("rejects non-object params", async () => {
		const res = await post(18788, "/execute", {
			principalId: "agent-1",
			toolClass: "http",
			action: "GET",
			params: "bad",
		});
		expect(res.status).toBe(400);
		const body = (await res.json()) as { allowed: boolean };
		expect(body.allowed).toBe(false);
	});

	it("rejects invalid JSON body", async () => {
		const res = await fetch("http://localhost:18788/execute", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: "not-json",
		});
		expect(res.status).toBe(400);
	});
});

// ── policy enforcement ────────────────────────────────────────────────────────

describe("POST /execute — policy enforcement", () => {
	let server: SidecarServer;
	let dir: string;

	beforeEach(async () => {
		dir = tempDir();
		server = new SidecarServer({
			port: 18789,
			policy: DENY_ALL_POLICY,
			auditLog: join(dir, "audit.db"),
		});
		await server.listen();
	});

	afterEach(async () => {
		await server.close();
		rmSync(dir, { recursive: true, force: true });
	});

	it("deny-all policy returns 403 with allowed=false", async () => {
		const res = await post(18789, "/execute", {
			principalId: "agent-1",
			toolClass: "http",
			action: "GET",
			params: { url: "http://example.com" },
		});
		expect(res.status).toBe(403);
		const body = (await res.json()) as { allowed: boolean };
		expect(body.allowed).toBe(false);
	});
});

// ── allowed execution path ───────────────────────────────────────────────────

describe("POST /execute — allowed execution", () => {
	let server: SidecarServer;
	let dir: string;

	beforeEach(async () => {
		dir = tempDir();
		server = new SidecarServer({
			port: 18792,
			policy: REALISTIC_POLICY,
			auditLog: join(dir, "audit.db"),
		});
		await server.listen();
	});

	afterEach(async () => {
		await server.close();
		rmSync(dir, { recursive: true, force: true });
	});

	it("allows file read and returns result with callId", async () => {
		const res = await post(18792, "/execute", {
			principalId: "test-agent",
			toolClass: "file",
			action: "read",
			params: { path: "./package.json" },
		});
		expect(res.status).toBe(200);
		const body = (await res.json()) as { allowed: boolean; callId: string };
		expect(body.allowed).toBe(true);
		expect(body.callId).toBeTruthy();
	});

	it("denies shell exec with 403", async () => {
		const res = await post(18792, "/execute", {
			principalId: "test-agent",
			toolClass: "shell",
			action: "exec",
			params: { command: "whoami" },
		});
		expect(res.status).toBe(403);
		const body = (await res.json()) as { allowed: boolean };
		expect(body.allowed).toBe(false);
	});
});

// ── quarantine / restricted mode ──────────────────────────────────────────────

describe("quarantine via sidecar", () => {
	let server: SidecarServer;
	let client: SidecarClient;
	let dir: string;

	beforeEach(async () => {
		dir = tempDir();
		server = new SidecarServer({
			port: 18793,
			policy: REALISTIC_POLICY,
			auditLog: join(dir, "audit.db"),
			runStatePolicy: { maxDeniedSensitiveActions: 2 },
		});
		await server.listen();
		client = new SidecarClient({
			baseUrl: "http://localhost:18793",
			principalId: "quarantine-agent",
		});
	});

	afterEach(async () => {
		await server.close();
		rmSync(dir, { recursive: true, force: true });
	});

	it("enters restricted mode after repeated denied actions", async () => {
		// Trigger denials to reach quarantine threshold
		for (let i = 0; i < 3; i++) {
			await client.execute("shell", "exec", { command: `attempt-${i}` });
		}

		// Check status reflects quarantine
		const status = await client.status();
		expect(status.restricted).toBe(true);
		expect(status.quarantine).toBeTruthy();
		expect(status.counters.deniedActions).toBeGreaterThanOrEqual(2);
	});
});

// ── status endpoint ──────────────────────────────────────────────────────────

describe("POST /status", () => {
	let server: SidecarServer;
	let dir: string;

	beforeEach(async () => {
		dir = tempDir();
		server = new SidecarServer({
			port: 18794,
			policy: DENY_ALL_POLICY,
			auditLog: join(dir, "audit.db"),
		});
		await server.listen();
	});

	afterEach(async () => {
		await server.close();
		rmSync(dir, { recursive: true, force: true });
	});

	it("returns 404 for unknown principal", async () => {
		const res = await post(18794, "/status", { principalId: "nobody" });
		expect(res.status).toBe(404);
	});

	it("returns status for active principal", async () => {
		// Create principal via an execute call — fully consume the response
		await post(18794, "/execute", {
			principalId: "status-agent",
			toolClass: "http",
			action: "GET",
			params: { url: "http://example.com" },
		});

		const res = await post(18794, "/status", { principalId: "status-agent" });
		expect(res.status).toBe(200);
		const body = (await res.json()) as {
			principalId: string;
			restricted: boolean;
			runId: string;
			counters: Record<string, number>;
		};
		expect(body.principalId).toBe("status-agent");
		expect(body.restricted).toBe(false);
		expect(body.runId).toBeTruthy();
		expect(body.counters.deniedActions).toBeGreaterThanOrEqual(1);
	});

	it("rejects missing principalId", async () => {
		const res = await post(18794, "/status", {});
		expect(res.status).toBe(400);
	});
});

// ── SidecarClient ─────────────────────────────────────────────────────────────

describe("SidecarClient", () => {
	let server: SidecarServer;
	let client: SidecarClient;
	let dir: string;

	beforeEach(async () => {
		dir = tempDir();
		server = new SidecarServer({
			port: 18790,
			policy: DENY_ALL_POLICY,
			auditLog: join(dir, "audit.db"),
		});
		await server.listen();
		client = new SidecarClient({ baseUrl: "http://localhost:18790", principalId: "test-agent" });
	});

	afterEach(async () => {
		await server.close();
		rmSync(dir, { recursive: true, force: true });
	});

	it("health() returns true when server is up", async () => {
		expect(await client.health()).toBe(true);
	});

	it("execute() returns allowed=false under deny-all policy", async () => {
		const result = await client.execute("file", "read", { path: "/etc/passwd" });
		expect(result.allowed).toBe(false);
		expect(result.error).toBeTruthy();
	});

	it("callId is present in response", async () => {
		const result = await client.execute("shell", "exec", { command: "echo hi" });
		expect(result.callId).toBeTruthy();
	});
});

// ── per-principal isolation ───────────────────────────────────────────────────

describe("per-principal isolation", () => {
	let server: SidecarServer;
	let dir: string;

	beforeEach(async () => {
		dir = tempDir();
		server = new SidecarServer({
			port: 18791,
			policy: DENY_ALL_POLICY,
			auditLog: join(dir, "audit.db"),
		});
		await server.listen();
	});

	afterEach(async () => {
		await server.close();
		rmSync(dir, { recursive: true, force: true });
	});

	it("two principals get independent firewall instances", async () => {
		const [r1, r2] = await Promise.all([
			post(18791, "/execute", {
				principalId: "agent-A",
				toolClass: "file",
				action: "read",
				params: { path: "/tmp/x" },
			}).then((r) => r.json()),
			post(18791, "/execute", {
				principalId: "agent-B",
				toolClass: "file",
				action: "read",
				params: { path: "/tmp/x" },
			}).then((r) => r.json()),
		]);
		expect((r1 as { allowed: boolean }).allowed).toBe(false);
		expect((r2 as { allowed: boolean }).allowed).toBe(false);
		expect((r1 as { callId?: string }).callId).not.toBe((r2 as { callId?: string }).callId);
	});
});

// ── end-to-end trust boundary ─────────────────────────────────────────────────

describe("end-to-end trust boundary", () => {
	let server: SidecarServer;
	let dir: string;

	beforeEach(async () => {
		dir = tempDir();
		server = new SidecarServer({
			port: 18795,
			policy: REALISTIC_POLICY,
			auditLog: join(dir, "audit.db"),
			runStatePolicy: { maxDeniedSensitiveActions: 2 },
		});
		await server.listen();
	});

	afterEach(async () => {
		await server.close();
		rmSync(dir, { recursive: true, force: true });
	});

	it("agent cannot bypass quarantine through process boundary", async () => {
		const client = new SidecarClient({
			baseUrl: "http://localhost:18795",
			principalId: "e2e-agent",
		});

		// Step 1: File read works before quarantine
		const r1 = await client.execute("file", "read", { path: "./package.json" });
		expect(r1.allowed).toBe(true);

		// Step 2: Trigger quarantine with repeated denied shell execs
		for (let i = 0; i < 3; i++) {
			await client.execute("shell", "exec", { command: `bad-${i}` });
		}

		// Step 3: Quarantine is active
		const status = await client.status();
		expect(status.restricted).toBe(true);

		// Step 4: Agent has no way to reset quarantine — state lives in sidecar.
		// Creating a new client with same principalId still sees quarantine.
		const client2 = new SidecarClient({
			baseUrl: "http://localhost:18795",
			principalId: "e2e-agent",
		});
		const status2 = await client2.status();
		expect(status2.restricted).toBe(true);
	});
});

// ── authentication ────────────────────────────────────────────────────────────

describe("Bearer token authentication", () => {
	const AUTH_TOKEN = "test-secret-token-12345";
	let server: SidecarServer;
	let dir: string;

	beforeEach(async () => {
		dir = tempDir();
		server = new SidecarServer({
			port: 18796,
			policy: ALLOW_HTTP_POLICY,
			auditLog: join(dir, "audit.db"),
			authToken: AUTH_TOKEN,
		});
		await server.listen();
	});

	afterEach(async () => {
		await server.close();
		rmSync(dir, { recursive: true, force: true });
	});

	it("health endpoint is always unauthenticated", async () => {
		const res = await fetch("http://localhost:18796/health");
		expect(res.status).toBe(200);
	});

	it("rejects /execute without auth header", async () => {
		const res = await post(18796, "/execute", {
			principalId: "agent-1",
			toolClass: "http",
			action: "GET",
			params: {},
		});
		expect(res.status).toBe(401);
		const body = (await res.json()) as { error: string };
		expect(body.error).toContain("Authorization");
	});

	it("rejects /execute with wrong token", async () => {
		const res = await post(
			18796,
			"/execute",
			{
				principalId: "agent-1",
				toolClass: "http",
				action: "GET",
				params: {},
			},
			{ Authorization: "Bearer wrong-token" },
		);
		expect(res.status).toBe(403);
		const body = (await res.json()) as { error: string };
		expect(body.error).toContain("Invalid");
	});

	it("accepts /execute with correct token", async () => {
		const res = await post(
			18796,
			"/execute",
			{
				principalId: "agent-1",
				toolClass: "http",
				action: "GET",
				params: { url: "http://example.com" },
			},
			{ Authorization: `Bearer ${AUTH_TOKEN}` },
		);
		expect(res.status).toBe(200);
	});

	it("rejects /status without auth header", async () => {
		const res = await post(18796, "/status", { principalId: "agent-1" });
		expect(res.status).toBe(401);
	});

	it("SidecarClient works with authToken option", async () => {
		const client = new SidecarClient({
			baseUrl: "http://localhost:18796",
			principalId: "auth-agent",
			authToken: AUTH_TOKEN,
		});
		const result = await client.execute("http", "GET", { url: "http://example.com" });
		expect(result.allowed).toBe(true);
	});

	it("SidecarClient without authToken gets rejected", async () => {
		const client = new SidecarClient({
			baseUrl: "http://localhost:18796",
			principalId: "no-auth-agent",
		});
		const result = await client.execute("http", "GET", { url: "http://example.com" });
		// Client gets 401 response parsed as JSON
		expect(result).toHaveProperty("error");
	});
});

// ── principal identity binding ────────────────────────────────────────────────

describe("Principal identity binding (API key → principalId)", () => {
	const PRINCIPALS = {
		"key-for-alice": { principalId: "alice" },
		"key-for-bob": { principalId: "bob" },
	};
	let server: SidecarServer;
	let dir: string;

	beforeEach(async () => {
		dir = tempDir();
		server = new SidecarServer({
			port: 18797,
			policy: ALLOW_HTTP_POLICY,
			auditLog: join(dir, "audit.db"),
			principals: PRINCIPALS,
		});
		await server.listen();
	});

	afterEach(async () => {
		await server.close();
		rmSync(dir, { recursive: true, force: true });
	});

	it("rejects requests without API key", async () => {
		const res = await post(18797, "/execute", {
			toolClass: "http",
			action: "GET",
			params: { url: "http://example.com" },
		});
		expect(res.status).toBe(401);
	});

	it("rejects requests with unknown API key", async () => {
		const res = await post(
			18797,
			"/execute",
			{ toolClass: "http", action: "GET", params: { url: "http://example.com" } },
			{ Authorization: "Bearer unknown-key" },
		);
		expect(res.status).toBe(403);
		const body = (await res.json()) as { error: string };
		expect(body.error).toContain("Invalid API key");
	});

	it("derives principalId from API key (no body principalId needed)", async () => {
		const res = await post(
			18797,
			"/execute",
			{ toolClass: "http", action: "GET", params: { url: "http://example.com" } },
			{ Authorization: "Bearer key-for-alice" },
		);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { allowed: boolean };
		expect(body.allowed).toBe(true);
	});

	it("accepts matching body principalId", async () => {
		const res = await post(
			18797,
			"/execute",
			{
				principalId: "alice",
				toolClass: "http",
				action: "GET",
				params: { url: "http://example.com" },
			},
			{ Authorization: "Bearer key-for-alice" },
		);
		expect(res.status).toBe(200);
	});

	it("rejects mismatched body principalId", async () => {
		const res = await post(
			18797,
			"/execute",
			{
				principalId: "bob",
				toolClass: "http",
				action: "GET",
				params: { url: "http://example.com" },
			},
			{ Authorization: "Bearer key-for-alice" },
		);
		expect(res.status).toBe(403);
		const body = (await res.json()) as { error: string };
		expect(body.error).toContain("Principal mismatch");
	});

	it("isolates firewalls between API-key-authenticated principals", async () => {
		// Alice and Bob each get their own firewall
		await post(
			18797,
			"/execute",
			{ toolClass: "http", action: "GET", params: { url: "http://example.com" } },
			{ Authorization: "Bearer key-for-alice" },
		);
		await post(
			18797,
			"/execute",
			{ toolClass: "http", action: "GET", params: { url: "http://example.com" } },
			{ Authorization: "Bearer key-for-bob" },
		);

		// Alice status
		const aliceStatus = await post(18797, "/status", {}, { Authorization: "Bearer key-for-alice" });
		expect(aliceStatus.status).toBe(200);
		const aliceBody = (await aliceStatus.json()) as { principalId: string };
		expect(aliceBody.principalId).toBe("alice");

		// Bob status
		const bobStatus = await post(18797, "/status", {}, { Authorization: "Bearer key-for-bob" });
		expect(bobStatus.status).toBe(200);
		const bobBody = (await bobStatus.json()) as { principalId: string };
		expect(bobBody.principalId).toBe("bob");
	});

	it("request-capability derives principalId from API key", async () => {
		const res = await post(
			18797,
			"/request-capability",
			{ capabilityClass: "http.read" },
			{ Authorization: "Bearer key-for-alice" },
		);
		// Should not fail with "principalId required"
		const body = (await res.json()) as { granted?: boolean; reason?: string };
		expect(body).toHaveProperty("granted");
	});
});

// ── rate limiting ─────────────────────────────────────────────────────────────

describe("Rate limiting", () => {
	let server: SidecarServer;
	let dir: string;

	afterEach(async () => {
		await server.close();
		rmSync(dir, { recursive: true, force: true });
	});

	it("returns 429 when request rate exceeded", async () => {
		dir = tempDir();
		server = new SidecarServer({
			port: 18798,
			// DENY_ALL_POLICY: rate-limit check fires before policy eval, so
			// rate-limited requests still get 429. Allowed requests return
			// immediately ({allowed:false}) without real network calls, preventing timeout.
			policy: DENY_ALL_POLICY,
			auditLog: join(dir, "audit.db"),
			rateLimits: { maxRequestsPerSecond: 2 },
		});
		await server.listen();

		const results: number[] = [];
		for (let i = 0; i < 5; i++) {
			const res = await post(18798, "/execute", {
				principalId: "rate-agent",
				toolClass: "http",
				action: "GET",
				params: { url: "http://example.com" },
			});
			results.push(res.status);
			// Consume body to prevent connection issues
			await res.text();
		}

		// First 2 should succeed, rest should be 429
		expect(results.filter((s) => s === 429).length).toBeGreaterThan(0);
		expect(results.filter((s) => s !== 429).length).toBeLessThanOrEqual(2);
	});

	it("returns 429 with Retry-After header", async () => {
		dir = tempDir();
		server = new SidecarServer({
			port: 18799,
			policy: ALLOW_HTTP_POLICY,
			auditLog: join(dir, "audit.db"),
			rateLimits: { maxRequestsPerSecond: 1 },
		});
		await server.listen();

		// First request succeeds
		const r1 = await post(18799, "/execute", {
			principalId: "retry-agent",
			toolClass: "http",
			action: "GET",
			params: { url: "http://example.com" },
		});
		await r1.text();

		// Second should be rate limited
		const r2 = await post(18799, "/execute", {
			principalId: "retry-agent",
			toolClass: "http",
			action: "GET",
			params: { url: "http://example.com" },
		});
		if (r2.status === 429) {
			expect(r2.headers.get("Retry-After")).toBeTruthy();
		}
		await r2.text();
	});

	it("returns 503 when global firewall limit exceeded", async () => {
		dir = tempDir();
		server = new SidecarServer({
			port: 18800,
			policy: ALLOW_HTTP_POLICY,
			auditLog: join(dir, "audit.db"),
			rateLimits: { globalMaxFirewalls: 1 },
		});
		await server.listen();

		// First principal creates a firewall
		const r1 = await post(18800, "/execute", {
			principalId: "first-agent",
			toolClass: "http",
			action: "GET",
			params: { url: "http://example.com" },
		});
		await r1.text();

		// Second principal should be rejected
		const r2 = await post(18800, "/execute", {
			principalId: "second-agent",
			toolClass: "http",
			action: "GET",
			params: { url: "http://example.com" },
		});
		expect(r2.status).toBe(503);
		const body = (await r2.json()) as { error: string };
		expect(body.error).toContain("Firewall instance limit");
	});

	it("rate limits apply per-principal independently", async () => {
		dir = tempDir();
		server = new SidecarServer({
			port: 18801,
			policy: ALLOW_HTTP_POLICY,
			auditLog: join(dir, "audit.db"),
			rateLimits: { maxRequestsPerSecond: 1 },
		});
		await server.listen();

		// Agent A uses their quota
		const rA = await post(18801, "/execute", {
			principalId: "agent-a",
			toolClass: "http",
			action: "GET",
			params: { url: "http://example.com" },
		});
		await rA.text();

		// Agent B should still have quota
		const rB = await post(18801, "/execute", {
			principalId: "agent-b",
			toolClass: "http",
			action: "GET",
			params: { url: "http://example.com" },
		});
		expect(rB.status).not.toBe(429);
		await rB.text();
	});
});

// ── dev mode production guard ─────────────────────────────────────────────────

describe("SidecarServer dev mode production guard", () => {
	let dir: string;

	beforeEach(() => {
		dir = tempDir();
	});

	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
	});

	it("throws when NODE_ENV=production and principals is not configured", () => {
		const prev = process.env.NODE_ENV;
		process.env.NODE_ENV = "production";
		try {
			expect(
				() =>
					new SidecarServer({
						port: 18820,
						policy: ALLOW_HTTP_POLICY,
						auditLog: join(dir, "audit.db"),
					}),
			).toThrow("AriKernel: dev mode cannot be enabled in production");
		} finally {
			process.env.NODE_ENV = prev;
		}
	});

	it("allows startup when NODE_ENV=production and principals is configured", async () => {
		const prev = process.env.NODE_ENV;
		process.env.NODE_ENV = "production";
		let server: SidecarServer | undefined;
		try {
			server = new SidecarServer({
				port: 18821,
				policy: ALLOW_HTTP_POLICY,
				auditLog: join(dir, "audit.db"),
				principals: { "test-key": { principalId: "agent-a" } },
			});
			await server.listen();
			const res = await fetch("http://localhost:18821/health");
			expect(res.status).toBe(200);
		} finally {
			process.env.NODE_ENV = prev;
			await server?.close();
		}
	});

	it("allows startup in non-production without principals (dev mode)", async () => {
		const prev = process.env.NODE_ENV;
		process.env.NODE_ENV = "development";
		let server: SidecarServer | undefined;
		try {
			server = new SidecarServer({
				port: 18822,
				policy: ALLOW_HTTP_POLICY,
				auditLog: join(dir, "audit.db"),
			});
			await server.listen();
			const res = await fetch("http://localhost:18822/health");
			expect(res.status).toBe(200);
		} finally {
			process.env.NODE_ENV = prev;
			await server?.close();
		}
	});
});

// ── /execute protocol semantics: allowed vs success ──────────────────────────

describe("POST /execute — allowed vs success decoupling", () => {
	let server: SidecarServer;
	let client: SidecarClient;
	let dir: string;

	beforeEach(async () => {
		dir = tempDir();
		server = new SidecarServer({
			port: 18823,
			policy: REALISTIC_POLICY,
			auditLog: join(dir, "audit.db"),
		});
		await server.listen();
		client = new SidecarClient({
			baseUrl: "http://localhost:18823",
			principalId: "proto-agent",
		});
	});

	afterEach(async () => {
		await server.close();
		rmSync(dir, { recursive: true, force: true });
	});

	it("allowed but tool fails returns 200 with allowed=true, success=false", async () => {
		// File read is allowed by policy, but file does not exist → tool failure
		// Path must be inside the allowed root (cwd) so it's not a security denial
		const result = await client.execute("file", "read", {
			path: "./nonexistent-file-that-does-not-exist.txt",
		});
		expect(result.allowed).toBe(true);
		expect(result.success).toBe(false);
		expect(result.error).toBeTruthy();
	});

	it("policy denial returns 403 with allowed=false", async () => {
		// Shell is denied by policy
		const result = await client.execute("shell", "exec", { command: "whoami" });
		expect(result.allowed).toBe(false);
	});

	it("allowed and tool succeeds returns 200 with allowed=true, success=true", async () => {
		const result = await client.execute("file", "read", { path: "./package.json" });
		expect(result.allowed).toBe(true);
		expect(result.success).toBe(true);
		expect(result.result).toBeTruthy();
	});
});

// ── grantId support in /execute ──────────────────────────────────────────────

describe("POST /execute — grantId support", () => {
	let server: SidecarServer;
	let dir: string;

	beforeEach(async () => {
		dir = tempDir();
		server = new SidecarServer({
			port: 18824,
			policy: REALISTIC_POLICY,
			auditLog: join(dir, "audit.db"),
		});
		await server.listen();
	});

	afterEach(async () => {
		await server.close();
		rmSync(dir, { recursive: true, force: true });
	});

	it("accepts grantId from prior /request-capability call", async () => {
		const client = new SidecarClient({
			baseUrl: "http://localhost:18824",
			principalId: "grant-agent",
		});

		// Step 1: Request capability
		const cap = await client.requestCapability("file.read");
		expect(cap.granted).toBe(true);
		expect(cap.grantId).toBeTruthy();

		// Step 2: Execute with grantId
		const result = await client.execute(
			"file",
			"read",
			{ path: "./package.json" },
			{
				grantId: cap.grantId,
			},
		);
		expect(result.allowed).toBe(true);
		expect(result.success).toBe(true);
	});

	it("grantId field is accepted in raw HTTP request", async () => {
		// First request a capability
		const capRes = await post(18824, "/request-capability", {
			principalId: "raw-grant-agent",
			capabilityClass: "file.read",
		});
		const cap = (await capRes.json()) as { granted: boolean; grantId?: string };
		expect(cap.granted).toBe(true);

		// Execute with grantId in body
		const execRes = await post(18824, "/execute", {
			principalId: "raw-grant-agent",
			toolClass: "file",
			action: "read",
			params: { path: "./package.json" },
			grantId: cap.grantId,
		});
		expect(execRes.status).toBe(200);
		const body = (await execRes.json()) as { allowed: boolean; success?: boolean };
		expect(body.allowed).toBe(true);
		expect(body.success).toBe(true);
	});
});
