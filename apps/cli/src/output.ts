import type { AuditEvent, Decision, RunContext, ToolCall } from "@arikernel/core";

const VERDICT_COLORS: Record<string, string> = {
	allow: "\x1b[32m", // green
	deny: "\x1b[31m", // red
	"require-approval": "\x1b[33m", // yellow
};
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const CYAN = "\x1b[36m";
const MAGENTA = "\x1b[35m";

export function printDecision(toolCall: ToolCall, decision: Decision): void {
	const color = VERDICT_COLORS[decision.verdict] ?? "";
	const verdict = `${color}${decision.verdict.toUpperCase()}${RESET}`;
	const rule = decision.matchedRule?.name ?? "implicit deny";

	console.log(`${BOLD}[${verdict}${BOLD}]${RESET} ${toolCall.toolClass}.${toolCall.action}`);
	console.log(`  ${DIM}Rule: ${rule}${RESET}`);
	console.log(`  ${DIM}Reason: ${decision.reason}${RESET}`);

	if (decision.taintLabels.length > 0) {
		const sources = decision.taintLabels.map((t) => t.source).join(", ");
		console.log(`  ${DIM}Taint: ${sources}${RESET}`);
	}
}

export function printAuditEvent(event: AuditEvent, verbose = false): void {
	// Handle quarantine/system events with special formatting
	if (event.toolCall.toolClass === "_system") {
		printQuarantineEvent(event, verbose);
		return;
	}

	const color = VERDICT_COLORS[event.decision.verdict] ?? "";
	const verdict = event.decision.verdict.toUpperCase().padEnd(5);
	const token = event.toolCall.grantId
		? `[token:${event.toolCall.grantId.slice(0, 8)}...]`
		: "[no token]";
	const duration = event.result?.durationMs != null ? `${event.result.durationMs}ms` : "-";

	console.log(
		`  ${DIM}#${event.sequence}${RESET} ${color}${BOLD}${verdict}${RESET} ` +
			`${event.toolCall.toolClass}.${event.toolCall.action} ` +
			`${DIM}${token}  ${duration}${RESET}`,
	);
	console.log(`     ${DIM}Reason: ${event.decision.reason}${RESET}`);

	if (event.toolCall.taintLabels.length > 0) {
		const sources = event.toolCall.taintLabels.map((t) => `${t.source}:${t.origin}`).join(", ");
		console.log(`     ${DIM}Taint:  ${sources}${RESET}`);
	}

	if (verbose) {
		const rule = event.decision.matchedRule?.name ?? "implicit deny";
		console.log(`     ${DIM}Rule:   ${rule}${RESET}`);
		console.log(`     ${DIM}Hash:   ${event.hash.slice(0, 16)}...${RESET}`);
		if (event.toolCall.parameters) {
			const params = JSON.stringify(event.toolCall.parameters);
			const display = params.length > 80 ? `${params.slice(0, 80)}...` : params;
			console.log(`     ${DIM}Params: ${display}${RESET}`);
		}
	}

	console.log("");
}

function printQuarantineEvent(event: AuditEvent, verbose: boolean): void {
	const params = event.toolCall.parameters;
	const triggerType = (params.triggerType as string) ?? "unknown";
	const ruleId = params.ruleId as string | undefined;

	console.log(
		`  ${DIM}#${event.sequence}${RESET} ${MAGENTA}${BOLD}QUARANTINE${RESET} ` +
			`${YELLOW}${BOLD}Run entered restricted mode${RESET}`,
	);
	console.log(`     ${MAGENTA}Trigger: ${triggerType}${ruleId ? ` (${ruleId})` : ""}${RESET}`);
	console.log(`     ${MAGENTA}Reason:  ${event.decision.reason}${RESET}`);

	if (verbose && params.counters) {
		const counters = params.counters as Record<string, number>;
		console.log(
			`     ${DIM}Counters: denied=${counters.deniedActions}, egress=${counters.externalEgressAttempts}, sensitive=${counters.sensitiveFileReadAttempts}${RESET}`,
		);
	}
	if (verbose && params.matchedEvents) {
		const matched = params.matchedEvents as Array<{ type: string; toolClass?: string }>;
		const summary = matched
			.map((e) => `${e.type}${e.toolClass ? `(${e.toolClass})` : ""}`)
			.join(" → ");
		console.log(`     ${DIM}Pattern: ${summary}${RESET}`);
	}

	console.log("");
}

export function printRunHeader(ctx: RunContext): void {
	console.log(`\n${CYAN}${BOLD}${"─".repeat(56)}${RESET}`);
	console.log(`${CYAN}${BOLD} Audit Replay${RESET}`);
	console.log(`${CYAN}${BOLD}${"─".repeat(56)}${RESET}`);
	console.log(`  ${DIM}Run ID:${RESET}    ${ctx.runId}`);
	console.log(`  ${DIM}Principal:${RESET} ${ctx.principalId}`);
	console.log(`  ${DIM}Started:${RESET}   ${ctx.startedAt}`);
	if (ctx.endedAt) {
		console.log(`  ${DIM}Ended:${RESET}     ${ctx.endedAt}`);
	}
	console.log(`${CYAN}${BOLD}${"─".repeat(56)}${RESET}\n`);
}

export function printReplaySummary(events: AuditEvent[], valid: boolean): void {
	const counts = { allow: 0, deny: 0, "require-approval": 0, quarantine: 0 };
	for (const e of events) {
		if (e.toolCall.toolClass === "_system") {
			counts.quarantine++;
		} else {
			counts[e.decision.verdict]++;
		}
	}

	console.log(`${CYAN}${BOLD}${"─".repeat(56)}${RESET}`);
	console.log(`${BOLD} Summary${RESET}\n`);
	console.log(`  Total events:       ${BOLD}${events.length}${RESET}`);
	console.log(`  Allowed:            ${GREEN}${counts.allow}${RESET}`);
	console.log(`  Denied:             ${RED}${counts.deny}${RESET}`);
	if (counts["require-approval"] > 0) {
		console.log(
			`  Approval required:  ${VERDICT_COLORS["require-approval"]}${counts["require-approval"]}${RESET}`,
		);
	}
	if (counts.quarantine > 0) {
		console.log(`  Quarantine events:  ${MAGENTA}${counts.quarantine}${RESET}`);
	}
	console.log("");

	const integrityColor = valid ? GREEN : RED;
	const integrityLabel = valid ? "VALID" : "BROKEN";
	console.log(`  Hash chain:         ${integrityColor}${BOLD}${integrityLabel}${RESET}`);
	console.log(`${CYAN}${BOLD}${"─".repeat(56)}${RESET}\n`);
}
