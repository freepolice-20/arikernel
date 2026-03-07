/**
 * Agent Firewall - Vertical Slice Demo
 *
 * Demonstrates the full intercept pipeline:
 * 1. Agent sends a tool call request
 * 2. Firewall checks capabilities
 * 3. Policy engine evaluates rules
 * 4. Taint labels are tracked
 * 5. Decision is enforced
 * 6. Audit event is logged with hash chain
 *
 * Run: pnpm demo
 */

import { ToolCallDeniedError, type TaintLabel } from '@agent-firewall/core';
import { createFirewall } from '@agent-firewall/runtime';
import { resolve } from 'node:path';

const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const RESET = '\x1b[0m';

function header(text: string): void {
	console.log(`\n${CYAN}${BOLD}${'='.repeat(60)}${RESET}`);
	console.log(`${CYAN}${BOLD}  ${text}${RESET}`);
	console.log(`${CYAN}${BOLD}${'='.repeat(60)}${RESET}\n`);
}

function step(n: number, text: string): void {
	console.log(`${YELLOW}${BOLD}--- Step ${n}: ${text} ---${RESET}\n`);
}

async function main() {
	header('Agent Firewall - Vertical Slice Demo');

	const policyPath = resolve(import.meta.dirname ?? '.', '..', 'policies', 'safe-defaults.yaml');
	const auditPath = resolve(import.meta.dirname ?? '.', '..', 'demo-audit.db');

	// Create a firewall instance
	const firewall = createFirewall({
		principal: {
			name: 'demo-agent',
			capabilities: [
				{
					toolClass: 'http',
					actions: ['get'],
					constraints: { allowedHosts: ['api.github.com', 'httpbin.org'] },
				},
				{
					toolClass: 'file',
					actions: ['read'],
					constraints: { allowedPaths: ['./examples/**', './policies/**'] },
				},
				{
					toolClass: 'shell',
					actions: ['exec'],
					constraints: { allowedCommands: ['echo', 'date'] },
				},
			],
		},
		policies: policyPath,
		auditLog: auditPath,
		hooks: {
			onDecision(toolCall, decision) {
				const color = decision.verdict === 'allow' ? GREEN : decision.verdict === 'deny' ? RED : YELLOW;
				console.log(`  ${DIM}Decision:${RESET} ${color}${decision.verdict.toUpperCase()}${RESET}`);
				console.log(`  ${DIM}Rule: ${decision.matchedRule?.name ?? 'implicit deny'}${RESET}`);
				console.log(`  ${DIM}Reason: ${decision.reason}${RESET}`);
			},
			async onApprovalRequired(toolCall, decision) {
				console.log(`  ${YELLOW}[APPROVAL REQUIRED]${RESET} Auto-approving for demo purposes.`);
				return true;
			},
		},
	});

	console.log(`${DIM}Firewall started. Run ID: ${firewall.runId}${RESET}`);
	console.log(`${DIM}Policy: ${policyPath}${RESET}`);
	console.log(`${DIM}Audit: ${auditPath}${RESET}`);

	// -------------------------------------------------------
	// Step 1: ALLOWED - HTTP GET to an allowed host
	// -------------------------------------------------------
	step(1, 'HTTP GET to allowed host (should ALLOW)');
	try {
		const result = await firewall.execute({
			toolClass: 'http',
			action: 'get',
			parameters: { url: 'https://httpbin.org/get' },
		});
		console.log(`  ${GREEN}Success!${RESET} Status: ${(result.data as any)?.status ?? 'ok'}`);
		console.log(`  ${DIM}Duration: ${result.durationMs}ms${RESET}`);
	} catch (err) {
		console.log(`  ${RED}Unexpected error: ${err}${RESET}`);
	}

	// -------------------------------------------------------
	// Step 2: DENIED - HTTP GET to unauthorized host
	// -------------------------------------------------------
	step(2, 'HTTP GET to unauthorized host (should DENY)');
	try {
		await firewall.execute({
			toolClass: 'http',
			action: 'get',
			parameters: { url: 'https://evil.com/steal-data' },
		});
		console.log(`  ${RED}ERROR: Should have been denied!${RESET}`);
	} catch (err) {
		if (err instanceof ToolCallDeniedError) {
			console.log(`  ${GREEN}Correctly denied!${RESET}`);
		}
	}

	// -------------------------------------------------------
	// Step 3: DENIED - Shell command with web-tainted input
	// -------------------------------------------------------
	step(3, 'Shell command with web-tainted input (should DENY by taint policy)');
	const webTaint: TaintLabel[] = [
		{ source: 'web', origin: 'untrusted-site.com', confidence: 1.0, addedAt: new Date().toISOString() },
	];
	try {
		await firewall.execute({
			toolClass: 'shell',
			action: 'exec',
			parameters: { command: 'echo hello' },
			taintLabels: webTaint,
		});
		console.log(`  ${RED}ERROR: Should have been denied!${RESET}`);
	} catch (err) {
		if (err instanceof ToolCallDeniedError) {
			console.log(`  ${GREEN}Correctly denied! Taint-aware policy caught it.${RESET}`);
		}
	}

	// -------------------------------------------------------
	// Step 4: REQUIRE-APPROVAL - Shell command without taint
	// -------------------------------------------------------
	step(4, 'Shell command without taint (should REQUIRE-APPROVAL, auto-approved)');
	try {
		const result = await firewall.execute({
			toolClass: 'shell',
			action: 'exec',
			parameters: { command: 'echo "Hello from Agent Firewall"' },
		});
		console.log(`  ${GREEN}Executed after approval!${RESET}`);
		console.log(`  ${DIM}Output: ${JSON.stringify((result.data as any)?.stdout?.trim())}${RESET}`);
	} catch (err) {
		console.log(`  ${RED}Error: ${err}${RESET}`);
	}

	// -------------------------------------------------------
	// Step 5: DENIED - No capability for database
	// -------------------------------------------------------
	step(5, 'Database query without capability (should DENY)');
	try {
		await firewall.execute({
			toolClass: 'database',
			action: 'query',
			parameters: { query: 'SELECT * FROM users' },
		});
		console.log(`  ${RED}ERROR: Should have been denied!${RESET}`);
	} catch (err) {
		if (err instanceof ToolCallDeniedError) {
			console.log(`  ${GREEN}Correctly denied! No capability for database.${RESET}`);
		}
	}

	// -------------------------------------------------------
	// Step 6: Replay the audit log
	// -------------------------------------------------------
	step(6, 'Replay audit log');
	const replay = firewall.replay();
	if (replay) {
		console.log(`  ${DIM}Events in this run: ${replay.events.length}${RESET}`);
		console.log(`  ${DIM}Hash chain integrity: ${replay.integrity.valid ? `${GREEN}VALID` : `${RED}BROKEN`}${RESET}`);
		console.log('');
		for (const event of replay.events) {
			const color = event.decision.verdict === 'allow' ? GREEN : event.decision.verdict === 'deny' ? RED : YELLOW;
			console.log(
				`  ${DIM}#${event.sequence}${RESET} ${color}${event.decision.verdict.toUpperCase().padEnd(7)}${RESET} ` +
				`${event.toolCall.toolClass}.${event.toolCall.action} ` +
				`${DIM}(${event.result?.durationMs ?? 0}ms)${RESET}`
			);
		}
	}

	// -------------------------------------------------------
	// Done
	// -------------------------------------------------------
	firewall.close();

	header('Demo Complete');
	console.log(`Audit log saved to: ${auditPath}`);
	console.log(`Run ID: ${firewall.runId}`);
	console.log(`\nReplay with: ${DIM}pnpm exec tsx apps/cli/src/main.ts replay --db ${auditPath} ${firewall.runId}${RESET}`);
	console.log('');
}

main().catch(console.error);
