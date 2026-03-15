/**
 * Generic JS/TS Wrapper — AriKernel Integration Example
 *
 * Demonstrates the universal wrapTool() pattern for any JS/TS application.
 * No framework needed — just wrap your tool functions with AriKernel.
 *
 * Run:
 *   npx tsx examples/generic-wrapper/agent.ts
 *   arikernel trace --latest
 *   arikernel replay --latest --step
 */

import { resolve } from "node:path";
import { ToolCallDeniedError } from "@arikernel/core";
import type { ToolCallRequest } from "@arikernel/core";
import { createFirewall } from "@arikernel/runtime";

// ── Inline wrapTool (same as @arikernel/adapters wrapTool) ──────────

function wrapTool(firewall: ReturnType<typeof createFirewall>, toolClass: string, action: string) {
	return async (parameters: Record<string, unknown>) => {
		const capClass =
			toolClass === "shell"
				? "shell.exec"
				: `${toolClass}.${["get", "read", "query", "list"].includes(action) ? "read" : "write"}`;
		const grant = firewall.requestCapability(capClass as any);
		if (!grant.granted) throw new Error(grant.reason ?? "Capability denied");
		return firewall.execute({
			toolClass: toolClass as ToolCallRequest["toolClass"],
			action,
			parameters,
			grantId: grant.grant?.id,
		});
	};
}

// ── Colors ──────────────────────────────────────────────────────────

const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const CYAN = "\x1b[36m";
const RESET = "\x1b[0m";

// ── Example ─────────────────────────────────────────────────────────

async function main() {
	const auditDb = resolve("arikernel-audit.db");

	const firewall = createFirewall({
		principal: {
			name: "my-app",
			capabilities: [
				{ toolClass: "http", actions: ["get"], constraints: { allowedHosts: ["api.example.com"] } },
				{ toolClass: "file", actions: ["read"], constraints: { allowedPaths: ["./data/**"] } },
			],
		},
		policies: [
			{
				id: "allow-http-get",
				name: "Allow GET",
				priority: 100,
				match: { toolClass: "http" as const, action: "get" },
				decision: "allow" as const,
				reason: "Allowed",
			},
			{
				id: "allow-file-read",
				name: "Allow reads",
				priority: 100,
				match: { toolClass: "file" as const, action: "read" },
				decision: "allow" as const,
				reason: "Allowed",
			},
		],
		auditLog: auditDb,
	});

	// Wrap your tool functions — that's it
	const httpGet = wrapTool(firewall, "http", "get");
	const fileRead = wrapTool(firewall, "file", "read");

	console.log(`\n${CYAN}${BOLD}${"═".repeat(60)}${RESET}`);
	console.log(`${CYAN}${BOLD}  Generic Wrapper — AriKernel Demo${RESET}`);
	console.log(`${CYAN}${BOLD}${"═".repeat(60)}${RESET}\n`);

	// Call 1: HTTP GET (allowed)
	console.log(
		`${YELLOW}${BOLD}Call 1${RESET} ${BOLD}httpGet("https://api.example.com/users")${RESET}`,
	);
	try {
		await httpGet({ url: "https://api.example.com/users" });
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET}\n`);
	} catch (err: any) {
		console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}— ${err.message}${RESET}\n`);
	}

	// Call 2: File read within allowed path (allowed)
	console.log(`${YELLOW}${BOLD}Call 2${RESET} ${BOLD}fileRead("./data/config.json")${RESET}`);
	try {
		await fileRead({ path: "./data/config.json" });
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET}\n`);
	} catch (err: any) {
		console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}— ${err.message}${RESET}\n`);
	}

	// Call 3: File read outside allowed path (blocked)
	console.log(`${YELLOW}${BOLD}Call 3${RESET} ${BOLD}fileRead("/etc/passwd")${RESET}`);
	try {
		await fileRead({ path: "/etc/passwd" });
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET}\n`);
	} catch (err: any) {
		console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}— ${err.message}${RESET}\n`);
	}

	firewall.close();

	console.log(`${CYAN}${BOLD}Forensic follow-up:${RESET}`);
	console.log(`  arikernel trace --latest --db ${auditDb}`);
	console.log(`  arikernel replay --latest --step --db ${auditDb}\n`);
}

main().catch(console.error);
