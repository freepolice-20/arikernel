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
 *   npx tsx examples/demo-sidecar.ts
 */

import type { PolicyRule, TaintLabel } from "@arikernel/core";
import { now } from "@arikernel/core";
import { SidecarClient, SidecarServer } from "@arikernel/sidecar";

const DEMO_PORT = 18800;
const AUDIT_PATH = "./demo-sidecar-audit.db";

// ── Policy ────────────────────────────────────────────────────────────────────
// Priority: lower number = evaluated first. First match wins.

const policies: PolicyRule[] = [
	{
		id: "allow-file-read",
		name: "Allow file reads",
		priority: 20,
		match: { toolClass: "file", action: "read" },
		decision: "allow",
		reason: "File reads allowed",
	},
	{
		id: "deny-shell",
		name: "Deny shell execution",
		priority: 100,
		match: { toolClass: "shell" },
		decision: "deny",
		reason: "Shell execution is prohibited",
	},
	{
		id: "deny-tainted-file-write",
		name: "Deny tainted file writes",
		priority: 150,
		match: { toolClass: "file", action: "write", taintLabels: ["web:*"] },
		decision: "deny",
		reason: "Cannot write web-tainted data to filesystem",
	},
	{
		id: "deny-default",
		name: "Default deny",
		priority: 900,
		match: {},
		decision: "deny",
		reason: "Deny by default",
	},
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function webTaint(origin: string): TaintLabel {
	return { source: "web", origin, confidence: 1.0, addedAt: now() };
}

// ── Demo ──────────────────────────────────────────────────────────────────────

const server = new SidecarServer({ port: DEMO_PORT, policy: policies, auditLog: AUDIT_PATH });
await server.listen();
console.log(`\nAriKernel sidecar demo — listening on port ${DEMO_PORT}\n`);

const client = new SidecarClient({
	baseUrl: `http://localhost:${DEMO_PORT}`,
	principalId: "demo-agent",
});

interface DemoStep {
	label: string;
	toolClass: string;
	action: string;
	params: Record<string, unknown>;
	taint?: TaintLabel[];
}

const steps: DemoStep[] = [
	{
		label: "File read (allowed by policy)",
		toolClass: "file",
		action: "read",
		params: { path: "./package.json" },
	},
	{
		label: "Shell exec (denied by policy)",
		toolClass: "shell",
		action: "exec",
		params: { command: "cat /etc/passwd" },
	},
	{
		label: "File write with web taint (denied — tainted data)",
		toolClass: "file",
		action: "write",
		params: { path: "/tmp/output.txt", content: "exfil" },
		taint: [webTaint("api.example.com")],
	},
	{
		label: "Database query (denied by default)",
		toolClass: "database",
		action: "query",
		params: { query: "SELECT * FROM users" },
	},
];

console.log("Running demo calls via SidecarClient:\n");

for (const step of steps) {
	const result = await client.execute(
		step.toolClass as Parameters<typeof client.execute>[0],
		step.action,
		step.params,
		step.taint,
	);
	const verdict = result.allowed ? "ALLOW" : "DENY ";
	const detail = result.allowed
		? result.result !== undefined
			? `result: ${JSON.stringify(result.result).slice(0, 60)}`
			: "no data"
		: `reason: ${result.error ?? "(none)"}`;
	console.log(`  ${verdict}  ${step.label}`);
	console.log(`           ${detail}`);
}

// Show status
const status = await client.status();
console.log("\nPrincipal status:");
console.log(`  Restricted: ${status.restricted}`);
console.log(`  Denied actions: ${status.counters.deniedActions}`);

await server.close();
console.log("\nSidecar demo complete. Audit log written to:", AUDIT_PATH);
