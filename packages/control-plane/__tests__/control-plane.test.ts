import { afterEach, describe, expect, it } from "vitest";
import {
	ControlPlaneClient,
	ControlPlaneError,
	ControlPlaneServer,
	DecisionSigner,
	DecisionVerifier,
	NonceStore,
	generateSigningKey,
} from "../src/index.js";

const TEST_KEY = generateSigningKey();
const AUTH_TOKEN = "test-secret-token";

const ALLOW_HTTP_POLICY = [
	{
		id: "allow-http",
		name: "Allow HTTP",
		priority: 10,
		match: { toolClass: "http" as const },
		decision: "allow" as const,
		reason: "HTTP allowed",
	},
];

const DENY_SHELL_POLICY = [
	{
		id: "deny-shell",
		name: "Deny shell",
		priority: 5,
		match: { toolClass: "shell" as const },
		decision: "deny" as const,
		reason: "Shell execution forbidden",
	},
	{
		id: "allow-http",
		name: "Allow HTTP",
		priority: 10,
		match: { toolClass: "http" as const },
		decision: "allow" as const,
		reason: "HTTP allowed",
	},
];

let server: ControlPlaneServer | null = null;

afterEach(async () => {
	if (server) {
		await server.close();
		server = null;
	}
});

describe("ControlPlaneServer", () => {
	it("starts and responds to health checks", async () => {
		server = new ControlPlaneServer({
			signingKey: TEST_KEY,
			policy: ALLOW_HTTP_POLICY,
			port: 9191,
		});
		await server.listen();

		const client = new ControlPlaneClient({ baseUrl: "http://127.0.0.1:9191" });
		const healthy = await client.health();
		expect(healthy).toBe(true);
	});

	it("evaluates an allow decision with valid Ed25519 signature", async () => {
		server = new ControlPlaneServer({
			signingKey: TEST_KEY,
			policy: ALLOW_HTTP_POLICY,
			port: 9192,
		});
		await server.listen();

		const client = new ControlPlaneClient({ baseUrl: "http://127.0.0.1:9192" });
		const response = await client.requestDecision({
			principalId: "agent-1",
			toolClass: "http",
			action: "GET",
			parameters: { url: "https://example.com" },
			taintLabels: [],
			runId: "run-1",
			timestamp: new Date().toISOString(),
		});

		expect(response.decision).toBe("allow");
		// Ed25519 signature: 64 bytes = 128 hex chars
		expect(response.signature).toMatch(/^[0-9a-f]{128}$/);
		expect(response.nonce).toMatch(/^[0-9a-f]{32}$/);
		expect(response.policyVersion).toBe("1.0.0");
		expect(response.decisionId).toMatch(/^dec-/);
		expect(response.policyHash).toMatch(/^[0-9a-f]{16}$/);

		// Verify signature with the signer
		const signer = new DecisionSigner(TEST_KEY);
		expect(signer.verify(response)).toBe(true);
	});

	it("signature verifiable with public key only (DecisionVerifier)", async () => {
		server = new ControlPlaneServer({
			signingKey: TEST_KEY,
			policy: ALLOW_HTTP_POLICY,
			port: 9200,
		});
		await server.listen();

		const client = new ControlPlaneClient({ baseUrl: "http://127.0.0.1:9200" });
		const response = await client.requestDecision({
			principalId: "agent-1",
			toolClass: "http",
			action: "GET",
			parameters: {},
			taintLabels: [],
			runId: "run-1",
			timestamp: new Date().toISOString(),
		});

		// Verify using only the public key (no private seed)
		const verifier = new DecisionVerifier(server.publicKeyHex);
		expect(verifier.verify(response)).toBe(true);
	});

	it("evaluates a deny decision for shell calls", async () => {
		server = new ControlPlaneServer({
			signingKey: TEST_KEY,
			policy: DENY_SHELL_POLICY,
			port: 9193,
		});
		await server.listen();

		const client = new ControlPlaneClient({ baseUrl: "http://127.0.0.1:9193" });
		const response = await client.requestDecision({
			principalId: "agent-1",
			toolClass: "shell",
			action: "exec",
			parameters: { command: "rm -rf /" },
			taintLabels: [],
			runId: "run-1",
			timestamp: new Date().toISOString(),
		});

		expect(response.decision).toBe("deny");
		expect(response.reason).toContain("Shell execution forbidden");
	});

	it("records decisions in the persistent audit log", async () => {
		server = new ControlPlaneServer({
			signingKey: TEST_KEY,
			policy: ALLOW_HTTP_POLICY,
			port: 9194,
		});
		await server.listen();

		const client = new ControlPlaneClient({ baseUrl: "http://127.0.0.1:9194" });
		await client.requestDecision({
			principalId: "agent-1",
			toolClass: "http",
			action: "GET",
			parameters: { url: "https://example.com" },
			taintLabels: [],
			runId: "run-1",
			timestamp: new Date().toISOString(),
		});

		expect(server.audit.count).toBe(1);
		const rows = server.audit.queryRecent(10);
		expect(rows).toHaveLength(1);
		expect(rows[0].principal_id).toBe("agent-1");
		expect(rows[0].decision).toBe("allow");
		expect(rows[0].tool_class).toBe("http");
		expect(rows[0].action).toBe("GET");
		expect(rows[0].policy_version).toBe("1.0.0");
		expect(rows[0].signature).toMatch(/^[0-9a-f]{128}$/);
	});

	it("audit log stores multiple decisions and supports querying by principal", async () => {
		server = new ControlPlaneServer({
			signingKey: TEST_KEY,
			policy: ALLOW_HTTP_POLICY,
			port: 9201,
		});
		await server.listen();

		const client = new ControlPlaneClient({ baseUrl: "http://127.0.0.1:9201" });

		await client.requestDecision({
			principalId: "agent-1",
			toolClass: "http",
			action: "GET",
			parameters: {},
			taintLabels: [],
			runId: "run-1",
			timestamp: new Date().toISOString(),
		});
		await client.requestDecision({
			principalId: "agent-2",
			toolClass: "http",
			action: "POST",
			parameters: {},
			taintLabels: [],
			runId: "run-2",
			timestamp: new Date().toISOString(),
		});

		expect(server.audit.count).toBe(2);
		const agent1Rows = server.audit.queryByPrincipal("agent-1");
		expect(agent1Rows).toHaveLength(1);
		expect(agent1Rows[0].principal_id).toBe("agent-1");
	});

	it("provides replay protection via NonceStore", async () => {
		server = new ControlPlaneServer({
			signingKey: TEST_KEY,
			policy: ALLOW_HTTP_POLICY,
			port: 9195,
		});
		await server.listen();

		const client = new ControlPlaneClient({ baseUrl: "http://127.0.0.1:9195" });
		const response = await client.requestDecision({
			principalId: "agent-1",
			toolClass: "http",
			action: "GET",
			parameters: {},
			taintLabels: [],
			runId: "run-1",
			timestamp: new Date().toISOString(),
		});

		const signer = new DecisionSigner(TEST_KEY);
		const store = new NonceStore();

		expect(signer.verify(response, store)).toBe(true);
		// Replay same response — should be rejected
		expect(signer.verify(response, store)).toBe(false);
	});

	it("enforces authentication when authToken is set", async () => {
		server = new ControlPlaneServer({
			signingKey: TEST_KEY,
			policy: ALLOW_HTTP_POLICY,
			port: 9196,
			authToken: AUTH_TOKEN,
		});
		await server.listen();

		// Without auth token — should fail
		const unauthClient = new ControlPlaneClient({ baseUrl: "http://127.0.0.1:9196" });
		await expect(
			unauthClient.requestDecision({
				principalId: "agent-1",
				toolClass: "http",
				action: "GET",
				parameters: {},
				taintLabels: [],
				runId: "run-1",
				timestamp: new Date().toISOString(),
			}),
		).rejects.toThrow(ControlPlaneError);

		// With auth token — should succeed
		const authClient = new ControlPlaneClient({
			baseUrl: "http://127.0.0.1:9196",
			authToken: AUTH_TOKEN,
		});
		const response = await authClient.requestDecision({
			principalId: "agent-1",
			toolClass: "http",
			action: "GET",
			parameters: {},
			taintLabels: [],
			runId: "run-1",
			timestamp: new Date().toISOString(),
		});
		expect(response.decision).toBe("allow");
	});

	it("validates request body fields", async () => {
		server = new ControlPlaneServer({
			signingKey: TEST_KEY,
			policy: ALLOW_HTTP_POLICY,
			port: 9197,
		});
		await server.listen();

		// Missing runId and timestamp
		const res = await fetch("http://127.0.0.1:9197/decision", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				principalId: "agent-1",
				toolClass: "http",
				action: "GET",
				parameters: {},
			}),
		});

		expect(res.status).toBe(400);
		const body = await res.json();
		expect((body as { error: string }).error).toContain("runId");
	});

	it("exposes public key and policy hash", () => {
		server = new ControlPlaneServer({
			signingKey: TEST_KEY,
			policy: ALLOW_HTTP_POLICY,
			port: 9202,
		});

		expect(server.publicKeyHex).toMatch(/^[0-9a-f]{64}$/);
		expect(server.policyHash).toMatch(/^[0-9a-f]{16}$/);
	});

	it("rejects replayed request nonces (409 Conflict)", async () => {
		server = new ControlPlaneServer({
			signingKey: TEST_KEY,
			policy: ALLOW_HTTP_POLICY,
			port: 9203,
		});
		await server.listen();

		const baseRequest = {
			principalId: "agent-1",
			toolClass: "http",
			action: "GET",
			parameters: {},
			taintLabels: [],
			runId: "run-1",
			timestamp: new Date().toISOString(),
			requestNonce: "unique-nonce-12345",
		};

		// First request succeeds
		const res1 = await fetch("http://127.0.0.1:9203/decision", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(baseRequest),
		});
		expect(res1.status).toBe(200);

		// Replayed request with same nonce — rejected
		const res2 = await fetch("http://127.0.0.1:9203/decision", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(baseRequest),
		});
		expect(res2.status).toBe(409);
		const body = await res2.json();
		expect((body as { error: string }).error).toContain("Duplicate requestNonce");
	});

	it("rejects requests without requestNonce (mandatory for request binding)", async () => {
		server = new ControlPlaneServer({
			signingKey: TEST_KEY,
			policy: ALLOW_HTTP_POLICY,
			port: 9204,
		});
		await server.listen();

		const request = {
			principalId: "agent-1",
			toolClass: "http",
			action: "GET",
			parameters: {},
			taintLabels: [],
			runId: "run-1",
			timestamp: new Date().toISOString(),
		};

		// Request without nonce — should be rejected with 400
		const res = await fetch("http://127.0.0.1:9204/decision", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(request),
		});
		expect(res.status).toBe(400);
		const body = await res.json();
		expect((body as { error: string }).error).toContain("requestNonce is required");
	});

	it("audit store exports JSONL", async () => {
		server = new ControlPlaneServer({
			signingKey: TEST_KEY,
			policy: ALLOW_HTTP_POLICY,
			port: 9205,
		});
		await server.listen();

		const client = new ControlPlaneClient({ baseUrl: "http://127.0.0.1:9205" });
		await client.requestDecision({
			principalId: "agent-1",
			toolClass: "http",
			action: "GET",
			parameters: {},
			taintLabels: [],
			runId: "run-1",
			timestamp: new Date().toISOString(),
		});
		await client.requestDecision({
			principalId: "agent-2",
			toolClass: "http",
			action: "POST",
			parameters: {},
			taintLabels: [],
			runId: "run-2",
			timestamp: new Date().toISOString(),
		});

		const jsonl = server.audit.exportJsonl();
		const lines = jsonl.trim().split("\n");
		expect(lines).toHaveLength(2);

		const row1 = JSON.parse(lines[0]);
		expect(row1.principal_id).toBe("agent-1");

		const row2 = JSON.parse(lines[1]);
		expect(row2.principal_id).toBe("agent-2");
	});

	it("decision response includes full receipt fields", async () => {
		server = new ControlPlaneServer({
			signingKey: TEST_KEY,
			policy: ALLOW_HTTP_POLICY,
			port: 9206,
			policyVersion: "2.0.0",
			kernelBuild: "arikernel-test-build",
		});
		await server.listen();

		const client = new ControlPlaneClient({ baseUrl: "http://127.0.0.1:9206" });
		const response = await client.requestDecision({
			principalId: "agent-1",
			toolClass: "http",
			action: "GET",
			parameters: {},
			taintLabels: [],
			runId: "run-1",
			timestamp: new Date().toISOString(),
		});

		// All receipt fields present
		expect(response.decision).toBe("allow");
		expect(response.decisionId).toMatch(/^dec-\d+-[0-9a-f]{8}$/);
		expect(response.policyVersion).toBe("2.0.0");
		expect(response.policyHash).toMatch(/^[0-9a-f]{16}$/);
		expect(response.kernelBuild).toBe("arikernel-test-build");
		expect(response.timestamp).toBeTruthy();
		expect(response.nonce).toMatch(/^[0-9a-f]{32}$/);
		expect(response.signature).toMatch(/^[0-9a-f]{128}$/);
	});
});

describe("ControlPlaneServer production guard (NF-04)", () => {
	it("throws when NODE_ENV=production and authToken is not set", () => {
		const prev = process.env.NODE_ENV;
		process.env.NODE_ENV = "production";
		try {
			expect(
				() =>
					new ControlPlaneServer({
						signingKey: TEST_KEY,
						policy: ALLOW_HTTP_POLICY,
						port: 9300,
					}),
			).toThrow("AriKernel: control plane authToken is required in production");
		} finally {
			process.env.NODE_ENV = prev;
		}
	});

	it("allows startup when NODE_ENV=production and authToken is set", async () => {
		const prev = process.env.NODE_ENV;
		process.env.NODE_ENV = "production";
		let s: ControlPlaneServer | undefined;
		try {
			s = new ControlPlaneServer({
				signingKey: TEST_KEY,
				policy: ALLOW_HTTP_POLICY,
				port: 9301,
				authToken: "prod-token",
			});
			await s.listen();
			const res = await fetch("http://127.0.0.1:9301/health");
			expect(res.status).toBe(200);
		} finally {
			process.env.NODE_ENV = prev;
			await s?.close();
		}
	});

	it("allows startup in non-production without authToken", async () => {
		const prev = process.env.NODE_ENV;
		process.env.NODE_ENV = "development";
		let s: ControlPlaneServer | undefined;
		try {
			s = new ControlPlaneServer({
				signingKey: TEST_KEY,
				policy: ALLOW_HTTP_POLICY,
				port: 9302,
			});
			await s.listen();
			const res = await fetch("http://127.0.0.1:9302/health");
			expect(res.status).toBe(200);
		} finally {
			process.env.NODE_ENV = prev;
			await s?.close();
		}
	});
});

describe("Taint registry endpoints", () => {
	it("registers and queries taint labels", async () => {
		server = new ControlPlaneServer({
			signingKey: TEST_KEY,
			policy: ALLOW_HTTP_POLICY,
			port: 9198,
		});
		await server.listen();

		const client = new ControlPlaneClient({ baseUrl: "http://127.0.0.1:9198" });

		// Register taint
		const regResult = await client.registerTaint({
			principalId: "agent-1",
			runId: "run-1",
			labels: [
				{
					source: "web",
					origin: "https://evil.com",
					confidence: 0.95,
					addedAt: new Date().toISOString(),
				},
			],
			resourceIds: ["/shared/data.json"],
		});

		expect(regResult.registered).toBe(true);
		expect(regResult.count).toBe(1);

		// Query taint
		const queryResult = await client.queryTaint("/shared/data.json");
		expect(queryResult.resourceId).toBe("/shared/data.json");
		expect(queryResult.labels).toHaveLength(1);
		expect(queryResult.labels[0].origin).toBe("https://evil.com");
	});

	it("enriches decisions with global taint from registry", async () => {
		server = new ControlPlaneServer({
			signingKey: TEST_KEY,
			policy: [
				{
					id: "deny-tainted-http",
					name: "Deny tainted HTTP",
					priority: 5,
					match: { toolClass: "http", taintSources: ["web"] },
					decision: "deny" as const,
					reason: "Tainted request blocked",
				},
				{
					id: "allow-http",
					name: "Allow HTTP",
					priority: 10,
					match: { toolClass: "http" },
					decision: "allow" as const,
					reason: "HTTP allowed",
				},
			],
			port: 9199,
		});
		await server.listen();

		const client = new ControlPlaneClient({ baseUrl: "http://127.0.0.1:9199" });

		// Register taint on a resource
		await client.registerTaint({
			principalId: "agent-a",
			runId: "run-1",
			labels: [
				{
					source: "web",
					origin: "injected",
					confidence: 1.0,
					addedAt: new Date().toISOString(),
				},
			],
			resourceIds: ["https://api.example.com/data"],
		});

		// Another agent's request touching the tainted resource gets enriched
		const response = await client.requestDecision({
			principalId: "agent-b",
			toolClass: "http",
			action: "GET",
			parameters: { url: "https://api.example.com/data" },
			taintLabels: [],
			runId: "run-2",
			timestamp: new Date().toISOString(),
		});

		// The decision should reflect the global taint
		expect(response.taintLabels.length).toBeGreaterThan(0);
		expect(response.taintLabels.some((t) => t.origin === "injected")).toBe(true);
	});
});
