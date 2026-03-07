/**
 * Agent Firewall - Capability Issuance Demo
 *
 * Demonstrates dynamic capability tokens:
 * 1. Agent reads untrusted web content (gets web taint)
 * 2. Agent requests http.read capability (granted - clean context)
 * 3. Agent executes HTTP GET with the granted token
 * 4. Agent requests database.read with web-tainted provenance
 * 5. Issuance is DENIED because provenance is untrusted
 * 6. Agent requests database.read with clean provenance (granted)
 * 7. Audit replay shows the full decision chain
 *
 * Run: pnpm demo:capability
 */

import type { IssuanceDecision, TaintLabel } from '@agent-firewall/core';
import { ToolCallDeniedError } from '@agent-firewall/core';
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

function printIssuance(decision: IssuanceDecision): void {
	const color = decision.granted ? GREEN : RED;
	const verdict = decision.granted ? 'GRANTED' : 'DENIED';
	console.log(`  ${DIM}Issuance:${RESET} ${color}${verdict}${RESET}`);
	console.log(`  ${DIM}Reason: ${decision.reason}${RESET}`);

	if (decision.grant) {
		const lease = decision.grant.lease;
		console.log(`  ${DIM}Token ID: ${decision.grant.id}${RESET}`);
		console.log(`  ${DIM}Class: ${decision.grant.capabilityClass}${RESET}`);
		console.log(`  ${DIM}Lease: ${lease.maxCalls} calls, expires ${lease.expiresAt}${RESET}`);
	}

	if (decision.taintLabels.length > 0) {
		const sources = decision.taintLabels.map((t) => `${t.source}:${t.origin}`).join(', ');
		console.log(`  ${DIM}Taint context: ${sources}${RESET}`);
	}
}

async function main() {
	header('Agent Firewall - Capability Issuance Demo');

	const policyPath = resolve(import.meta.dirname ?? '.', '..', 'policies', 'safe-defaults.yaml');
	const auditPath = resolve(import.meta.dirname ?? '.', '..', 'demo-capability-audit.db');

	const firewall = createFirewall({
		principal: {
			name: 'research-agent',
			capabilities: [
				{
					toolClass: 'http',
					actions: ['get'],
					constraints: { allowedHosts: ['httpbin.org', 'api.github.com'] },
				},
				{
					toolClass: 'database',
					actions: ['query'],
					constraints: { allowedDatabases: ['analytics'] },
				},
			],
		},
		policies: policyPath,
		auditLog: auditPath,
		hooks: {
			onIssuance(request, decision) {
				const color = decision.granted ? GREEN : RED;
				console.log(
					`  ${DIM}[HOOK]${RESET} Capability ${color}${decision.granted ? 'GRANTED' : 'DENIED'}${RESET} ` +
					`for ${request.capabilityClass}`,
				);
			},
			onDecision(toolCall, decision) {
				const color = decision.verdict === 'allow' ? GREEN : RED;
				console.log(
					`  ${DIM}[HOOK]${RESET} Tool call ${color}${decision.verdict.toUpperCase()}${RESET} ` +
					`${toolCall.toolClass}.${toolCall.action}`,
				);
			},
		},
	});

	console.log(`${DIM}Firewall started. Run ID: ${firewall.runId}${RESET}`);

	// ----------------------------------------------------------
	// Step 1: Request http.read capability (clean context)
	// ----------------------------------------------------------
	step(1, 'Request http.read capability (clean context)');

	const httpDecision = firewall.requestCapability('http.read');
	printIssuance(httpDecision);

	if (!httpDecision.granted) {
		console.log(`  ${RED}Unexpected denial!${RESET}`);
		firewall.close();
		return;
	}

	// ----------------------------------------------------------
	// Step 2: Execute HTTP GET using the granted token
	// ----------------------------------------------------------
	step(2, 'Execute HTTP GET with capability token');

	try {
		const result = await firewall.execute({
			toolClass: 'http',
			action: 'get',
			parameters: { url: 'https://httpbin.org/json' },
			grantId: httpDecision.grant!.id,
		});
		console.log(`  ${GREEN}Success!${RESET} Status: ${(result.data as any)?.status}`);
		console.log(`  ${DIM}Duration: ${result.durationMs}ms${RESET}`);
	} catch (err) {
		console.log(`  ${RED}Error: ${err}${RESET}`);
	}

	// ----------------------------------------------------------
	// Step 3: Simulate reading untrusted web content (taint enters)
	// ----------------------------------------------------------
	step(3, 'Simulate reading untrusted web content');

	const webTaint: TaintLabel[] = [
		{
			source: 'web',
			origin: 'untrusted-news-site.com',
			confidence: 1.0,
			addedAt: new Date().toISOString(),
		},
	];

	console.log(`  ${YELLOW}Web taint acquired:${RESET} source=web, origin=untrusted-news-site.com`);
	console.log(`  ${DIM}This taint will propagate to subsequent capability requests.${RESET}`);

	// ----------------------------------------------------------
	// Step 4: Request database.read with web-tainted provenance
	// ----------------------------------------------------------
	step(4, 'Request database.read with web-tainted provenance (should DENY)');

	const dbDenied = firewall.requestCapability('database.read', {
		taintLabels: webTaint,
		justification: 'Need to query analytics based on web article',
	});
	printIssuance(dbDenied);

	if (dbDenied.granted) {
		console.log(`  ${RED}ERROR: Should have been denied!${RESET}`);
	} else {
		console.log(`  ${GREEN}Correctly denied! Taint-aware issuance blocked it.${RESET}`);
	}

	// ----------------------------------------------------------
	// Step 5: Try to execute database query WITHOUT a token
	//         Must be DENIED — protected actions require a grant
	// ----------------------------------------------------------
	step(5, 'Try database query without capability token (should DENY)');

	try {
		await firewall.execute({
			toolClass: 'database',
			action: 'query',
			parameters: { query: 'SELECT * FROM analytics.pageviews' },
			taintLabels: webTaint,
		});
		console.log(`  ${RED}ERROR: Executed without a capability token — enforcement is broken!${RESET}`);
	} catch (err) {
		if (err instanceof ToolCallDeniedError) {
			console.log(`  ${GREEN}Correctly denied! No capability token = no execution.${RESET}`);
			console.log(`  ${DIM}Reason: ${err.decision.reason}${RESET}`);
		}
	}

	// ----------------------------------------------------------
	// Step 6: Request database.read with clean provenance (granted)
	// ----------------------------------------------------------
	step(6, 'Request database.read with clean provenance (should GRANT)');

	const dbGranted = firewall.requestCapability('database.read', {
		justification: 'Need analytics data for scheduled report',
	});
	printIssuance(dbGranted);

	if (!dbGranted.granted) {
		console.log(`  ${RED}Unexpected denial!${RESET}`);
	} else {
		console.log(`  ${GREEN}Token issued! Agent can now query the database.${RESET}`);

		// Show active grants
		const grants = firewall.activeGrants();
		console.log(`\n  ${DIM}Active grants for this agent: ${grants.length}${RESET}`);
		for (const g of grants) {
			console.log(`    ${DIM}- ${g.capabilityClass} (${g.lease.callsUsed}/${g.lease.maxCalls} calls used)${RESET}`);
		}
	}

	// ----------------------------------------------------------
	// Step 7: Audit replay
	// ----------------------------------------------------------
	step(7, 'Audit replay');

	const replay = firewall.replay();
	if (replay) {
		console.log(`  ${DIM}Events in this run: ${replay.events.length}${RESET}`);
		console.log(
			`  ${DIM}Hash chain integrity: ${replay.integrity.valid ? `${GREEN}VALID` : `${RED}BROKEN`}${RESET}`,
		);
		console.log('');
		for (const event of replay.events) {
			const color =
				event.decision.verdict === 'allow'
					? GREEN
					: event.decision.verdict === 'deny'
						? RED
						: YELLOW;
			console.log(
				`  ${DIM}#${event.sequence}${RESET} ${color}${event.decision.verdict.toUpperCase().padEnd(7)}${RESET} ` +
					`${event.toolCall.toolClass}.${event.toolCall.action} ` +
					`${DIM}${event.toolCall.grantId ? `[token:${event.toolCall.grantId.slice(0, 8)}...]` : '[no token]'} ` +
					`(${event.result?.durationMs ?? 0}ms)${RESET}`,
			);
		}
	}

	// ----------------------------------------------------------
	// Done
	// ----------------------------------------------------------
	firewall.close();

	header('Demo Complete');
	console.log('Key takeaway: the agent was DENIED a database.read token when its');
	console.log('provenance chain included untrusted web content, but GRANTED one');
	console.log('when the context was clean. This is dynamic, taint-aware capability');
	console.log('issuance -- the core of Agent Firewall.\n');
	console.log(`${DIM}Audit log: ${auditPath}${RESET}`);
	console.log(`${DIM}Run ID: ${firewall.runId}${RESET}\n`);
}

main().catch(console.error);
