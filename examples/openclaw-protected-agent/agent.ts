/**
 * OpenClaw (formerly Moltbot, originally Clawdbot) — AriKernel Integration Example
 *
 * Demonstrates how AriKernel protects OpenClaw-compatible skill execution
 * at the tool boundary. Every skill call goes through capability checks,
 * policy evaluation, taint tracking, behavioral detection, and audit logging.
 *
 * Seam: skill/tool wrapper boundary
 * Support level: experimental compatibility layer
 *
 * Run:  pnpm demo:openclaw
 */

import { OpenClawAdapter } from "@arikernel/adapters";
import { ToolCallDeniedError } from "@arikernel/core";
import { createFirewall } from "@arikernel/runtime";

const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const CYAN = "\x1b[36m";
const RESET = "\x1b[0m";

async function main() {
	const firewall = createFirewall({
		principal: {
			name: "openclaw-agent",
			capabilities: [
				{ toolClass: "http", actions: ["get"], constraints: { allowedHosts: ["api.example.com"] } },
				{ toolClass: "file", actions: ["read"], constraints: { allowedPaths: ["./workspace/**"] } },
				{ toolClass: "database", actions: ["query"] },
			],
		},
		policies: [
			{
				id: "allow-http-get",
				name: "Allow HTTP GET",
				priority: 100,
				match: { toolClass: "http" as const, action: "get" },
				decision: "allow" as const,
			},
			{
				id: "allow-file-read",
				name: "Allow file reads",
				priority: 100,
				match: { toolClass: "file" as const, action: "read" },
				decision: "allow" as const,
			},
			{
				id: "allow-db-query",
				name: "Allow DB queries",
				priority: 100,
				match: { toolClass: "database" as const, action: "query" },
				decision: "allow" as const,
			},
		],
		auditLog: ":memory:",
		runStatePolicy: { maxDeniedSensitiveActions: 3, behavioralRules: true },
	});

	// Register stub executors for pipeline compliance
	for (const tc of ["http", "file", "database", "shell"]) {
		firewall.registerExecutor({
			toolClass: tc,
			async execute(toolCall) {
				return { callId: toolCall.id, success: true, data: null, durationMs: 0, taintLabels: [] };
			},
		});
	}

	// Create adapter and register OpenClaw-style skills
	const adapter = new OpenClawAdapter(firewall)
		.registerSkill(
			"web_search",
			"http",
			"get",
			(args) => `Search results for "${args.query}" from ${args.url}`,
			{ description: "Search the web via API" },
		)
		.registerSkill("read_document", "file", "read", (args) => `Document contents: [${args.path}]`, {
			description: "Read a document from workspace",
		})
		.registerSkill(
			"query_db",
			"database",
			"query",
			(args) => `Query result: 42 rows from ${args.table}`,
			{ description: "Query the database" },
		)
		.registerSkill("run_command", "shell", "exec", (args) => `Output of: ${args.cmd}`, {
			description: "Execute a shell command",
		});

	console.log(`\n${CYAN}${BOLD}${"=".repeat(60)}${RESET}`);
	console.log(`${CYAN}${BOLD}  OpenClaw — AriKernel Protection Demo${RESET}`);
	console.log(`${CYAN}${BOLD}${"=".repeat(60)}${RESET}`);
	console.log(`${DIM}  Run ID: ${firewall.runId}${RESET}`);
	console.log(`${DIM}  Skills: ${adapter.skillNames.join(", ")}${RESET}\n`);

	// Step 1: Allowed — web search to allowed host
	console.log(`${YELLOW}${BOLD}Step 1${RESET} ${BOLD}web_search (allowed host)${RESET}`);
	try {
		const result = await adapter.executeSkill("web_search", {
			query: "AriKernel security",
			url: "https://api.example.com/search",
		});
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET} ${DIM}${result}${RESET}\n`);
	} catch (err: any) {
		console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}${err.message}${RESET}\n`);
	}

	// Step 2: Allowed — read from workspace
	console.log(`${YELLOW}${BOLD}Step 2${RESET} ${BOLD}read_document (safe path)${RESET}`);
	try {
		const result = await adapter.executeSkill("read_document", { path: "./workspace/notes.md" });
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET} ${DIM}${result}${RESET}\n`);
	} catch (err: any) {
		console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}${err.message}${RESET}\n`);
	}

	// Step 3: Denied — read sensitive file outside workspace
	console.log(`${YELLOW}${BOLD}Step 3${RESET} ${BOLD}read_document (~/.env)${RESET}`);
	try {
		await adapter.executeSkill("read_document", { path: "~/.env" });
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET}\n`);
	} catch (err: any) {
		console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}${err.message}${RESET}\n`);
	}

	// Step 4: Denied — shell exec (no capability granted)
	console.log(`${YELLOW}${BOLD}Step 4${RESET} ${BOLD}run_command (no capability)${RESET}`);
	try {
		await adapter.executeSkill("run_command", { cmd: "cat /etc/passwd" });
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET}\n`);
	} catch (err: any) {
		console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}${err.message}${RESET}\n`);
	}

	console.log(`${CYAN}${BOLD}${"=".repeat(60)}${RESET}`);
	console.log(`  Restricted: ${firewall.isRestricted}`);
	console.log(`${CYAN}${BOLD}${"=".repeat(60)}${RESET}\n`);

	firewall.close();
}

main().catch(console.error);
