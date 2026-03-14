/**
 * End-to-end test: Sidecar thin-client mode.
 *
 * Proves that when a host Firewall is created with mode:"sidecar":
 *
 * 1. requestCapabilityAsync() routes to the sidecar (not local policy)
 * 2. execute() bypasses the local pipeline and routes to the sidecar
 * 3. Capability flow works end-to-end through the sidecar
 * 4. Denials from the sidecar surface as ToolCallDeniedError
 * 5. Local pipeline (policy engine, token store, behavioral rules) is NOT
 *    used as an authoritative decision source
 * 6. Local hooks still fire for observability
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ToolCallDeniedError } from "@arikernel/core";
import { Firewall, type FirewallHooks } from "@arikernel/runtime";
import { SidecarServer } from "../src/index.js";

function tempDir(): string {
	return mkdtempSync(join(tmpdir(), "arikernel-thin-client-test-"));
}

// Sidecar policy: allow HTTP reads and file reads, deny shell and everything else.
const SIDECAR_POLICY = [
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

// Host policy: ALLOW EVERYTHING. If local policy were authoritative in sidecar
// mode, shell calls would succeed. The fact that they're denied proves the
// sidecar is the authority, not the local policy engine.
const HOST_ALLOW_ALL_POLICY = [
	{
		id: "host-allow-all",
		name: "Host allows everything (should be irrelevant in sidecar mode)",
		priority: 1,
		match: {},
		decision: "allow" as const,
	},
];

describe("Sidecar thin-client mode — end-to-end", () => {
	let sidecar: SidecarServer;
	let firewall: Firewall;
	let dir: string;
	const PORT = 18850;

	const onDecisionSpy = vi.fn();
	const onExecuteSpy = vi.fn();

	beforeEach(async () => {
		dir = tempDir();
		onDecisionSpy.mockClear();
		onExecuteSpy.mockClear();

		// Start sidecar with restrictive policy
		sidecar = new SidecarServer({
			port: PORT,
			policy: SIDECAR_POLICY,
			auditLog: join(dir, "audit.db"),
		});
		await sidecar.listen();

		// Create host firewall with mode:"sidecar" and PERMISSIVE local policy.
		// If local policy evaluation were still happening, everything would be
		// allowed — but the sidecar should override with its restrictive policy.
		const hooks: FirewallHooks = {
			onDecision: onDecisionSpy,
			onExecute: onExecuteSpy,
		};

		firewall = new Firewall({
			principal: {
				name: "thin-client-agent",
				capabilities: [{ toolClass: "http" }, { toolClass: "file" }, { toolClass: "shell" }],
			},
			policies: HOST_ALLOW_ALL_POLICY,
			auditLog: ":memory:",
			mode: "sidecar",
			sidecar: {
				baseUrl: `http://localhost:${PORT}`,
				principalId: "thin-client-agent",
			},
			hooks,
		});
	});

	afterEach(async () => {
		firewall.close();
		await sidecar.close();
		rmSync(dir, { recursive: true, force: true });
	});

	// ── Capability flow ──────────────────────────────────────────────────────

	it("requestCapabilityAsync() routes to sidecar and returns grant", async () => {
		const decision = await firewall.requestCapabilityAsync("http.read");
		expect(decision.granted).toBe(true);
		expect(decision.grant).toBeDefined();
		expect(decision.grant?.id).toBeTruthy();
	});

	it("requestCapabilityAsync() returns denial for shell (sidecar policy)", async () => {
		const decision = await firewall.requestCapabilityAsync("shell.exec");
		expect(decision.granted).toBe(false);
	});

	it("requestCapability() sync returns synthetic grant in sidecar mode", () => {
		// Synchronous requestCapability returns a synthetic grant for backward compat.
		// The real decision comes from the sidecar on execute().
		const decision = firewall.requestCapability("http.read");
		expect(decision.granted).toBe(true);
		expect(decision.reason).toContain("sidecar");
	});

	// ── Execute: allowed path ────────────────────────────────────────────────

	it("execute() routes through sidecar (allowed action)", async () => {
		const result = await firewall.execute({
			toolClass: "file",
			action: "read",
			parameters: { path: "./package.json" },
		});

		expect(result.success).toBe(true);
		expect(result.callId).toBeTruthy();
	});

	it("execute() fires onExecute hook for observability", async () => {
		await firewall.execute({
			toolClass: "file",
			action: "read",
			parameters: { path: "./package.json" },
		});

		expect(onExecuteSpy).toHaveBeenCalledTimes(1);
		const [toolCall, toolResult] = onExecuteSpy.mock.calls[0];
		expect(toolCall.toolClass).toBe("file");
		expect(toolResult.success).toBe(true);
	});

	// ── Execute: denied path ─────────────────────────────────────────────────

	it("execute() raises ToolCallDeniedError for sidecar-denied action", async () => {
		// Local policy is ALLOW ALL, but sidecar policy denies shell.
		// If local policy were authoritative, this would succeed.
		await expect(
			firewall.execute({
				toolClass: "shell",
				action: "exec",
				parameters: { command: "whoami" },
			}),
		).rejects.toThrow(ToolCallDeniedError);
	});

	it("sidecar denial fires onDecision hook", async () => {
		try {
			await firewall.execute({
				toolClass: "shell",
				action: "exec",
				parameters: { command: "whoami" },
			});
		} catch {
			// expected
		}

		expect(onDecisionSpy).toHaveBeenCalledTimes(1);
		const [toolCall, decision] = onDecisionSpy.mock.calls[0];
		expect(toolCall.toolClass).toBe("shell");
		expect(decision.verdict).toBe("deny");
	});

	// ── Proves local pipeline is bypassed ────────────────────────────────────

	it("local allow-all policy does NOT override sidecar denial", async () => {
		// This is the key architectural test. The host has allow-all policy.
		// If local policy evaluation were still happening, shell.exec would be
		// allowed by the local pipeline. The fact that it throws proves the
		// local pipeline is bypassed and the sidecar is authoritative.
		let denied = false;
		try {
			await firewall.execute({
				toolClass: "shell",
				action: "exec",
				parameters: { command: "echo hello" },
			});
		} catch (e) {
			if (e instanceof ToolCallDeniedError) {
				denied = true;
			}
		}
		expect(denied).toBe(true);
	});

	it("local token store is not authoritative — execute works without local grant", async () => {
		// In embedded mode, execute() would fail without a grantId because the
		// local pipeline enforces tokens. In sidecar mode, the local token store
		// is not consulted — the sidecar auto-issues grants server-side.
		const result = await firewall.execute({
			toolClass: "file",
			action: "read",
			parameters: { path: "./package.json" },
		});

		// If the local token store were enforcing, this would throw
		// "Capability token required for protected action". Instead it succeeds.
		expect(result.success).toBe(true);
	});

	// ── Capability + execute flow ────────────────────────────────────────────

	it("full capability flow: requestCapabilityAsync → execute with grantId", async () => {
		const cap = await firewall.requestCapabilityAsync("file.read");
		expect(cap.granted).toBe(true);

		const result = await firewall.execute({
			toolClass: "file",
			action: "read",
			parameters: { path: "./package.json" },
			grantId: cap.grant?.id,
		});

		expect(result.success).toBe(true);
	});

	// ── Enforcement mode exposed correctly ───────────────────────────────────

	it("enforcementMode reports sidecar", () => {
		expect(firewall.enforcementMode).toBe("sidecar");
	});
});
