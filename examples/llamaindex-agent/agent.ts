/**
 * LlamaIndex TS — AriKernel Integration Example
 *
 * Demonstrates how AriKernel protects LlamaIndex-style tool functions.
 * Uses the LlamaIndexAdapter to create protected tool functions that route
 * through capability checks, policy, taint, and behavioral detection.
 *
 * Run:  pnpm demo:llamaindex
 */

import { LlamaIndexAdapter } from "@arikernel/adapters";
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
			name: "llamaindex-agent",
			capabilities: [
				{ toolClass: "http", actions: ["get"], constraints: { allowedHosts: ["api.example.com"] } },
				{ toolClass: "file", actions: ["read"], constraints: { allowedPaths: ["./docs/**"] } },
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

	// Register executors
	for (const tc of ["http", "file", "database"]) {
		firewall.registerExecutor({
			toolClass: tc,
			async execute(toolCall) {
				return {
					callId: toolCall.id,
					success: true,
					data: `${tc} result for ${JSON.stringify(toolCall.parameters)}`,
					durationMs: 1,
					taintLabels: [],
				};
			},
		});
	}

	// Create adapter and wrap tools (as you would for FunctionTool.from())
	const adapter = new LlamaIndexAdapter(firewall);
	const tools = adapter.protectTools({
		fetch_url: { toolClass: "http", action: "get" },
		read_file: { toolClass: "file", action: "read" },
		query_db: { toolClass: "database", action: "query" },
	});

	console.log(`\n${CYAN}${BOLD}${"═".repeat(60)}${RESET}`);
	console.log(`${CYAN}${BOLD}  LlamaIndex TS — AriKernel Protection Demo${RESET}`);
	console.log(`${CYAN}${BOLD}${"═".repeat(60)}${RESET}`);
	console.log(`${DIM}  Run ID: ${firewall.runId}${RESET}\n`);

	// Step 1: Allowed — fetch from allowed host
	console.log(`${YELLOW}${BOLD}Step 1${RESET} ${BOLD}fetch_url (allowed)${RESET}`);
	try {
		const result = await tools.fetch_url({ url: "https://api.example.com/data" });
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET} ${DIM}${result.data}${RESET}\n`);
	} catch (err: any) {
		console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}${err.message}${RESET}\n`);
	}

	// Step 2: Allowed — read from allowed path
	console.log(`${YELLOW}${BOLD}Step 2${RESET} ${BOLD}read_file (./docs/readme.md)${RESET}`);
	try {
		const result = await tools.read_file({ path: "./docs/readme.md" });
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET} ${DIM}${result.data}${RESET}\n`);
	} catch (err: any) {
		console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}${err.message}${RESET}\n`);
	}

	// Step 3: Denied — read sensitive file
	console.log(`${YELLOW}${BOLD}Step 3${RESET} ${BOLD}read_file (~/.env)${RESET}`);
	try {
		await tools.read_file({ path: "~/.env" });
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET}\n`);
	} catch (err: any) {
		console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}${err.message}${RESET}\n`);
	}

	// Step 4: Allowed — DB query
	console.log(`${YELLOW}${BOLD}Step 4${RESET} ${BOLD}query_db (allowed)${RESET}`);
	try {
		const result = await tools.query_db({ sql: "SELECT name FROM products" });
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET} ${DIM}${result.data}${RESET}\n`);
	} catch (err: any) {
		console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}${err.message}${RESET}\n`);
	}

	console.log(`${CYAN}${BOLD}${"═".repeat(60)}${RESET}`);
	console.log(`  Restricted: ${firewall.isRestricted}`);
	console.log(`${CYAN}${BOLD}${"═".repeat(60)}${RESET}\n`);

	firewall.close();
}

main().catch(console.error);
