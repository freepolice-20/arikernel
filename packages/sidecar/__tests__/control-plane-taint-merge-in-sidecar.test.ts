/**
 * Tests that taintLabels returned by a remote control-plane decision
 * are merged into the sidecar's run state, affecting subsequent enforcement.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { SidecarServer } from "../src/index.js";

// ── helpers ──────────────────────────────────────────────────────────

function tempDir(): string {
	return mkdtempSync(join(tmpdir(), "arikernel-taint-merge-test-"));
}

function post(port: number, path: string, body: unknown) {
	return fetch(`http://localhost:${port}${path}`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
}

/**
 * Fake control-plane server that always allows and optionally returns taintLabels.
 */
function startFakeControlPlane(
	port: number,
	taintLabels: unknown[] = [],
): Promise<{ close: () => Promise<void> }> {
	return new Promise((resolve) => {
		const server = createServer((_req, res) => {
			let data = "";
			_req.on("data", (chunk: Buffer) => {
				data += chunk.toString();
			});
			_req.on("end", () => {
				res.writeHead(200, { "Content-Type": "application/json" });
				res.end(
					JSON.stringify({
						decision: "allow",
						reason: "test-allow",
						signature: "a".repeat(128),
						nonce: "b".repeat(32),
						policyVersion: "1.0.0",
						decisionId: "dec-taint-test",
						policyHash: "0000000000000000",
						kernelBuild: "test",
						taintLabels,
					}),
				);
			});
		});

		server.listen(port, "127.0.0.1", () => {
			resolve({ close: () => new Promise((r) => server.close(() => r())) });
		});
	});
}

const ALLOW_ALL_POLICY = [
	{
		id: "allow-all",
		name: "Allow everything",
		priority: 500,
		match: {},
		decision: "allow" as const,
		reason: "Test: allow all",
	},
];

describe("Control-plane taint merge into sidecar run state", () => {
	let dir: string;
	let server: SidecarServer;
	let cpServer: Awaited<ReturnType<typeof startFakeControlPlane>>;

	afterEach(async () => {
		try {
			await server?.close();
		} catch {}
		try {
			await cpServer?.close();
		} catch {}
		try {
			rmSync(dir, { recursive: true, force: true });
		} catch {}
	});

	it("remote decision taintLabels are injected into run state", async () => {
		dir = tempDir();
		cpServer = await startFakeControlPlane(19300, [
			{
				source: "web",
				origin: "control-plane-policy",
				confidence: 0.9,
				addedAt: new Date().toISOString(),
			},
		]);

		server = new SidecarServer({
			port: 19301,
			policy: ALLOW_ALL_POLICY,
			auditLog: join(dir, "audit.db"),
			decisionMode: "remote",
			controlPlaneUrl: "http://127.0.0.1:19300",
			runStatePolicy: { maxDeniedSensitiveActions: 5, behavioralRules: true },
		});
		await server.listen();

		// First call: HTTP GET — CP returns taint labels, should still succeed
		const res1 = await post(19301, "/execute", {
			principalId: "agent-taint",
			toolClass: "http",
			action: "get",
			params: { url: "https://example.com" },
		});
		const body1 = (await res1.json()) as Record<string, unknown>;
		expect(body1.allowed).toBe(true);

		// Check run state via /status — should show tainted state
		const statusRes = await post(19301, "/status", { principalId: "agent-taint" });
		const statusBody = (await statusRes.json()) as Record<string, unknown>;
		expect(statusBody.restricted).toBeDefined();
	});

	it("subsequent shell call is blocked after CP injects web taint", async () => {
		dir = tempDir();
		cpServer = await startFakeControlPlane(19302, [
			{
				source: "web",
				origin: "cp-taint-injection",
				confidence: 1.0,
				addedAt: new Date().toISOString(),
			},
		]);

		server = new SidecarServer({
			port: 19303,
			policy: ALLOW_ALL_POLICY,
			auditLog: join(dir, "audit.db"),
			decisionMode: "remote",
			controlPlaneUrl: "http://127.0.0.1:19302",
			runStatePolicy: { maxDeniedSensitiveActions: 5, behavioralRules: true },
		});
		await server.listen();

		// First call: HTTP GET — CP returns web taint
		const res1 = await post(19303, "/execute", {
			principalId: "agent-taint-2",
			toolClass: "http",
			action: "get",
			params: { url: "https://example.com" },
		});
		const body1 = (await res1.json()) as Record<string, unknown>;
		expect(body1.allowed).toBe(true);

		// Second call: shell exec — should be blocked due to web taint (Rule 1)
		const res2 = await post(19303, "/execute", {
			principalId: "agent-taint-2",
			toolClass: "shell",
			action: "exec",
			params: { command: "ls" },
		});
		const body2 = (await res2.json()) as Record<string, unknown>;
		expect(body2.allowed).toBe(false);
	});
});
