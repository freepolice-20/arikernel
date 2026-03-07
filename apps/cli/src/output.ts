import type { AuditEvent, Decision, ToolCall } from '@agent-firewall/core';

const VERDICT_COLORS: Record<string, string> = {
	allow: '\x1b[32m',    // green
	deny: '\x1b[31m',     // red
	'require-approval': '\x1b[33m', // yellow
};
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';

export function printDecision(toolCall: ToolCall, decision: Decision): void {
	const color = VERDICT_COLORS[decision.verdict] ?? '';
	const verdict = `${color}${decision.verdict.toUpperCase()}${RESET}`;
	const rule = decision.matchedRule?.name ?? 'implicit deny';

	console.log(`${BOLD}[${verdict}${BOLD}]${RESET} ${toolCall.toolClass}.${toolCall.action}`);
	console.log(`  ${DIM}Rule: ${rule}${RESET}`);
	console.log(`  ${DIM}Reason: ${decision.reason}${RESET}`);

	if (decision.taintLabels.length > 0) {
		const sources = decision.taintLabels.map((t) => t.source).join(', ');
		console.log(`  ${DIM}Taint: ${sources}${RESET}`);
	}
}

export function printAuditEvent(event: AuditEvent): void {
	const color = VERDICT_COLORS[event.decision.verdict] ?? '';
	const verdict = `${color}${event.decision.verdict.toUpperCase()}${RESET}`;

	console.log(
		`${DIM}#${event.sequence}${RESET} ${verdict} ${event.toolCall.toolClass}.${event.toolCall.action} ` +
		`${DIM}(${event.result?.durationMs ?? 0}ms)${RESET}`
	);
}

export function printReplaySummary(events: AuditEvent[], valid: boolean): void {
	const counts = { allow: 0, deny: 0, 'require-approval': 0 };
	for (const e of events) {
		counts[e.decision.verdict]++;
	}

	console.log(`\n${BOLD}Run Summary${RESET}`);
	console.log(`  Total events: ${events.length}`);
	console.log(`  Allowed: ${VERDICT_COLORS.allow}${counts.allow}${RESET}`);
	console.log(`  Denied: ${VERDICT_COLORS.deny}${counts.deny}${RESET}`);
	console.log(`  Approval required: ${VERDICT_COLORS['require-approval']}${counts['require-approval']}${RESET}`);
	console.log(`  Hash chain integrity: ${valid ? '\x1b[32mVALID\x1b[0m' : '\x1b[31mBROKEN\x1b[0m'}`);
}
