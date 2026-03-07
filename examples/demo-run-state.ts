/**
 * AriKernel - Run-State Escalation Demo
 *
 * Demonstrates stateful enforcement: the firewall tracks cumulative
 * behavior across an entire agent run. When the agent repeatedly
 * attempts suspicious actions and gets denied, the run enters
 * "restricted mode" — only read-only safe actions are allowed.
 *
 * Phases:
 *   1. Agent makes a legitimate HTTP GET (allowed)
 *   2. Agent probes sensitive files (denied, counter increments)
 *   3. Agent attempts shell exec (denied, counter increments)
 *   4. After threshold exceeded, run enters restricted mode
 *   5. Agent tries HTTP POST — blocked by restricted mode
 *   6. Agent tries HTTP GET — still allowed (read-only safe action)
 *
 * Run: pnpm demo:run-state
 */

import { ToolCallDeniedError } from '@arikernel/core';
import { createFirewall } from '@arikernel/runtime';
import { resolve } from 'node:path';

// ── Terminal formatting ──────────────────────────────────────────────

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

function statusLine(fw: ReturnType<typeof createFirewall>): void {
	const c = fw.runStateCounters;
	const mode = fw.isRestricted
		? `${BG_MAGENTA}${WHITE}${BOLD} RESTRICTED ${RESET}`
		: `${GREEN}normal${RESET}`;
	console.log(
		`  ${DIM}Run state:${RESET} ${mode}  ` +
		`${DIM}denied=${c.deniedActions} caps=${c.capabilityRequests} ` +
		`egress=${c.externalEgressAttempts} sensitive=${c.sensitiveFileReadAttempts}${RESET}\n`,
	);
}

// ── Main demo ────────────────────────────────────────────────────────

async function main() {
	banner('Run-State Escalation Demo');

	console.log(`${DIM}Scenario: An AI agent starts with legitimate requests but then`);
	console.log(`probes sensitive files and attempts shell execution. After 3 denied`);
	console.log(`actions (configurable threshold), the run enters restricted mode.`);
	console.log(`In restricted mode, only read-only safe actions are allowed.${RESET}\n`);

	const policyPath = resolve(import.meta.dirname ?? '.', '..', 'policies', 'safe-defaults.yaml');
	const auditPath = resolve(import.meta.dirname ?? '.', '..', 'demo-run-state-audit.db');

	const firewall = createFirewall({
		principal: {
			name: 'suspicious-agent',
			capabilities: [
				{
					toolClass: 'http',
					actions: ['get', 'post'],
					constraints: { allowedHosts: ['api.github.com', 'httpbin.org'] },
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
			maxDeniedSensitiveActions: 3,
		},
	});

	info(`Firewall started. Run ID: ${firewall.runId}`);
	info(`Restricted mode threshold: 3 denied sensitive actions\n`);

	let allowed = 0;
	let denied = 0;

	// ── Phase 1: Legitimate action ──────────────────────────────────

	phase(1, 'Legitimate action: HTTP GET to api.github.com');

	const httpGrant = firewall.requestCapability('http.read');
	info(`Capability: ${httpGrant.granted ? `${GREEN}GRANTED${RESET}` : `${RED}DENIED${RESET}`}`);

	try {
		await firewall.execute({
			toolClass: 'http',
			action: 'get',
			parameters: { url: 'https://api.github.com/repos/example' },
			grantId: httpGrant.grant!.id,
		});
		console.log(`  ${BG_GREEN}${WHITE}${BOLD} ALLOWED ${RESET} ${GREEN}HTTP GET to api.github.com${RESET}`);
		allowed++;
	} catch (err) {
		if (err instanceof ToolCallDeniedError) {
			console.log(`  ${BG_RED}${WHITE}${BOLD} BLOCKED ${RESET} ${RED}${err.decision.reason}${RESET}`);
			denied++;
		}
	}
	statusLine(firewall);

	// ── Phase 2: Probe sensitive files ──────────────────────────────

	phase(2, 'Probing sensitive files (denied — builds up run state)');

	const sensitiveFiles = [
		'~/.ssh/id_rsa',
		'~/.aws/credentials',
		'/etc/shadow',
	];

	const fileGrant = firewall.requestCapability('file.read');
	info(`Capability: ${fileGrant.granted ? `${GREEN}GRANTED${RESET}` : `${RED}DENIED${RESET}`}`);

	for (const path of sensitiveFiles) {
		try {
			await firewall.execute({
				toolClass: 'file',
				action: 'read',
				parameters: { path },
				grantId: fileGrant.grant?.id,
			});
			console.log(`  ${BG_GREEN}${WHITE}${BOLD} ALLOWED ${RESET} ${GREEN}file.read ${path}${RESET}`);
			allowed++;
		} catch (err) {
			if (err instanceof ToolCallDeniedError) {
				console.log(`  ${BG_RED}${WHITE}${BOLD} BLOCKED ${RESET} ${RED}file.read ${path}${RESET}`);
				info(`Reason: ${err.decision.reason}`);
				denied++;
			}
		}
	}
	statusLine(firewall);

	// ── Phase 3: Check if restricted mode activated ─────────────────

	phase(3, 'Run-state check');

	if (firewall.isRestricted) {
		console.log(`  ${BG_MAGENTA}${WHITE}${BOLD} RESTRICTED MODE ACTIVATED ${RESET}`);
		console.log(`  ${MAGENTA}The run entered restricted mode at ${firewall.restrictedAt}${RESET}`);
		console.log(`  ${MAGENTA}Only read-only safe actions (http.get, file.read, db.query) are allowed.${RESET}\n`);
	} else {
		console.log(`  ${GREEN}Run is still in normal mode. Denied actions: ${firewall.runStateCounters.deniedActions}${RESET}\n`);
	}

	// ── Phase 4: Attempt HTTP POST in restricted mode ───────────────

	phase(4, 'Attempt HTTP POST (blocked by restricted mode)');

	const writeGrant = firewall.requestCapability('http.write');
	info(`Capability issuance for http.write: ${writeGrant.granted ? `${GREEN}GRANTED${RESET}` : `${RED}DENIED${RESET}`}`);
	if (!writeGrant.granted) {
		info(`Reason: ${writeGrant.reason}`);
	}

	// Even if we had a pre-existing write token, the pipeline blocks it
	try {
		await firewall.execute({
			toolClass: 'http',
			action: 'post',
			parameters: { url: 'https://httpbin.org/post', body: { data: 'exfiltrated' } },
		});
		console.log(`  ${BG_GREEN}${WHITE}${BOLD} ALLOWED ${RESET} ${RED}HTTP POST — should not happen!${RESET}`);
		allowed++;
	} catch (err) {
		if (err instanceof ToolCallDeniedError) {
			console.log(`  ${BG_RED}${WHITE}${BOLD} BLOCKED ${RESET} ${RED}HTTP POST blocked by restricted mode${RESET}`);
			info(`Reason: ${err.decision.reason}`);
			denied++;
		}
	}
	statusLine(firewall);

	// ── Phase 5: Attempt safe read-only action in restricted mode ───

	phase(5, 'Attempt HTTP GET in restricted mode (still allowed)');

	const readGrant = firewall.requestCapability('http.read');
	info(`Capability issuance for http.read: ${readGrant.granted ? `${GREEN}GRANTED${RESET}` : `${RED}DENIED${RESET}`}`);

	if (readGrant.granted) {
		try {
			await firewall.execute({
				toolClass: 'http',
				action: 'get',
				parameters: { url: 'https://api.github.com/repos/example' },
				grantId: readGrant.grant!.id,
			});
			console.log(`  ${BG_GREEN}${WHITE}${BOLD} ALLOWED ${RESET} ${GREEN}HTTP GET still works in restricted mode${RESET}`);
			allowed++;
		} catch (err) {
			if (err instanceof ToolCallDeniedError) {
				console.log(`  ${BG_RED}${WHITE}${BOLD} BLOCKED ${RESET} ${RED}${err.decision.reason}${RESET}`);
				denied++;
			}
		}
	}
	statusLine(firewall);

	// ── Phase 6: Summary ────────────────────────────────────────────

	phase(6, 'Results');

	const counters = firewall.runStateCounters;
	console.log(`  ${GREEN}${BOLD}Allowed:${RESET} ${allowed} action(s)`);
	console.log(`  ${RED}${BOLD}Denied:${RESET}  ${denied} action(s)\n`);
	console.log(`  ${BOLD}Run-State Counters:${RESET}`);
	console.log(`    Denied actions:              ${counters.deniedActions}`);
	console.log(`    Capability requests:         ${counters.capabilityRequests}`);
	console.log(`    Denied capability requests:  ${counters.deniedCapabilityRequests}`);
	console.log(`    External egress attempts:    ${counters.externalEgressAttempts}`);
	console.log(`    Sensitive file attempts:     ${counters.sensitiveFileReadAttempts}\n`);

	if (firewall.isRestricted) {
		console.log(`  ${BG_MAGENTA}${WHITE}${BOLD} RUN QUARANTINED ${RESET}`);
		console.log(`  ${MAGENTA}Restricted mode entered at ${firewall.restrictedAt}${RESET}`);
		console.log(`  ${MAGENTA}Agent was limited to read-only safe actions for the rest of the run.${RESET}\n`);
	}

	// ── Phase 7: Forensic audit trail ───────────────────────────────

	phase(7, 'Forensic audit trail');

	const events = firewall.getEvents();
	for (const event of events) {
		const verdict = event.decision.verdict;
		const color = verdict === 'allow' ? GREEN : RED;
		const icon = verdict === 'allow' ? 'ALLOW' : 'DENY ';
		const restricted = event.decision.reason.includes('restricted mode')
			? ` ${MAGENTA}[RESTRICTED]${RESET}`
			: '';

		console.log(
			`  ${DIM}#${event.sequence}${RESET} ${color}${BOLD}${icon}${RESET} ` +
			`${event.toolCall.toolClass}.${event.toolCall.action}` +
			`${restricted} ` +
			`${DIM}${event.toolCall.grantId ? `[token:${event.toolCall.grantId.slice(0, 8)}...]` : '[no token]'}${RESET}`,
		);
		console.log(`     ${DIM}Reason: ${event.decision.reason}${RESET}`);
		console.log('');
	}

	const replay = firewall.replay();
	if (replay) {
		const integrityColor = replay.integrity.valid ? GREEN : RED;
		const integrityLabel = replay.integrity.valid ? 'VALID' : 'BROKEN';
		console.log(`  ${DIM}Audit events: ${replay.events.length}${RESET}`);
		console.log(`  ${DIM}Hash chain integrity: ${integrityColor}${BOLD}${integrityLabel}${RESET}`);
		console.log(`  ${DIM}Run ID: ${firewall.runId}${RESET}`);
	}

	firewall.close();

	banner('Simulation Complete');
	console.log(`${DIM}The agent started normally but repeatedly probed sensitive files.`);
	console.log(`After 3 denied actions, the run entered restricted mode.`);
	console.log(`In restricted mode, only read-only actions were allowed —`);
	console.log(`HTTP POST was blocked, but HTTP GET still worked.${RESET}\n`);
	console.log(`${DIM}Replay: pnpm cli replay --db ${auditPath} --latest --verbose${RESET}\n`);
}

main().catch(console.error);
