/**
 * LangChain Middleware Demo — One-Line Agent Protection
 *
 * Shows how protectLangChainAgent() wraps an agent's tools with Ari Kernel
 * enforcement in a single function call. No manual firewall setup required.
 *
 * Run:  pnpm demo:middleware:langchain
 */

import { type LangChainTool, protectLangChainAgent } from "@arikernel/middleware";

const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const CYAN = "\x1b[36m";
const MAGENTA = "\x1b[35m";
const RESET = "\x1b[0m";

// ── Simulated LangChain tools ────────────────────────────────────────

const tools: LangChainTool[] = [
	{
		name: "web_search",
		description: "Search the web for information",
		func: async (query: string) => `Search results for "${query}": AI safety research from 2024...`,
	},
	{
		name: "read_file",
		description: "Read a local file",
		func: async (path: string) => `Contents of ${path}`,
	},
	{
		name: "run_shell",
		description: "Execute a shell command",
		func: async (cmd: string) => `Output of: ${cmd}`,
	},
];

// ── Simulated LangChain agent ────────────────────────────────────────

const agent = { tools, name: "research-assistant" };

// ── One-line protection ──────────────────────────────────────────────

const { agent: protectedAgent, firewall } = protectLangChainAgent(agent, {
	preset: "safe-research",
});

// ── Run scenarios ────────────────────────────────────────────────────

async function main() {
	console.log(`\n${CYAN}${BOLD}${"═".repeat(60)}${RESET}`);
	console.log(`${CYAN}${BOLD}  LangChain Middleware — One-Line Protection Demo${RESET}`);
	console.log(`${CYAN}${BOLD}${"═".repeat(60)}${RESET}`);
	console.log(`${DIM}  Run ID: ${firewall.runId}${RESET}`);
	console.log(`${DIM}  Preset: safe-research${RESET}\n`);

	// Step 1: Allowed — web search
	console.log(`${YELLOW}${BOLD}Step 1${RESET} ${BOLD}web_search (allowed)${RESET}`);
	try {
		const result = await protectedAgent.tools[0].func?.("AI safety");
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET} ${DIM}${result}${RESET}\n`);
	} catch (err: any) {
		console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}${err.message}${RESET}\n`);
	}

	// Step 2: Allowed — read safe file
	console.log(`${YELLOW}${BOLD}Step 2${RESET} ${BOLD}read_file (safe path)${RESET}`);
	try {
		const result = await protectedAgent.tools[1].func?.("./data/notes.txt");
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET} ${DIM}${result}${RESET}\n`);
	} catch (err: any) {
		console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}${err.message}${RESET}\n`);
	}

	// Step 3: Blocked — read sensitive file
	console.log(`${YELLOW}${BOLD}Step 3${RESET} ${BOLD}read_file (~/.ssh/id_rsa)${RESET}`);
	try {
		const result = await protectedAgent.tools[1].func?.("~/.ssh/id_rsa");
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET} ${DIM}${result}${RESET}\n`);
	} catch (err: any) {
		console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}${err.message}${RESET}\n`);
	}

	// Step 4: Blocked — shell exec
	console.log(`${YELLOW}${BOLD}Step 4${RESET} ${BOLD}run_shell (no capability)${RESET}`);
	try {
		const result = await protectedAgent.tools[2].func?.("whoami");
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET} ${DIM}${result}${RESET}\n`);
	} catch (err: any) {
		console.log(`  ${RED}${BOLD}BLOCKED${RESET} ${DIM}${err.message}${RESET}\n`);
	}

	// Summary
	console.log(`${CYAN}${BOLD}${"═".repeat(60)}${RESET}`);
	console.log(`  Quarantined: ${firewall.isRestricted}`);
	console.log(`${CYAN}${BOLD}${"═".repeat(60)}${RESET}\n`);
	console.log(`${DIM}The agent code never changed — protectLangChainAgent() wrapped${RESET}`);
	console.log(`${DIM}all tool calls through Ari Kernel transparently.${RESET}\n`);

	firewall.close();
}

main().catch(console.error);
