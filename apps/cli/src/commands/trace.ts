import { AuditStore, replayRun } from "@arikernel/audit-log";
import type { AuditEvent } from "@arikernel/core";

const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const CYAN = "\x1b[36m";
const MAGENTA = "\x1b[35m";
const RESET = "\x1b[0m";

const VERDICT_COLORS: Record<string, string> = {
	allow: GREEN,
	deny: RED,
	"require-approval": YELLOW,
};

function formatTimestamp(ts: string): string {
	try {
		const d = new Date(ts);
		return d.toLocaleTimeString("en-US", { hour12: false, fractionalSecondDigits: 3 });
	} catch {
		return ts;
	}
}

function printTraceEvent(event: AuditEvent): void {
	if (event.toolCall.toolClass === "_system") {
		console.log(`  ${DIM}│${RESET}`);
		console.log(`  ${MAGENTA}${BOLD}├─ QUARANTINE${RESET}`);
		console.log(`  ${DIM}│  ${MAGENTA}Run entered restricted mode${RESET}`);
		const params = event.toolCall.parameters;
		if (params.ruleId) {
			console.log(`  ${DIM}│  Rule: ${params.ruleId}${RESET}`);
		}
		console.log(`  ${DIM}│  ${event.decision.reason}${RESET}`);
		return;
	}

	const color = VERDICT_COLORS[event.decision.verdict] ?? "";
	const verdict = event.decision.verdict.toUpperCase();
	const time = formatTimestamp(event.timestamp);

	console.log(`  ${DIM}│${RESET}`);
	console.log(`  ${DIM}▼ ${time}${RESET}`);
	console.log(`  ${BOLD}${event.toolCall.toolClass}.${event.toolCall.action}${RESET}`);

	// Show taint if present
	if (event.toolCall.taintLabels.length > 0) {
		const sources = event.toolCall.taintLabels.map((t) => t.source).join(", ");
		console.log(`  ${DIM}taint: ${sources}${RESET}`);
	}

	// Show parameters summary
	if (event.toolCall.parameters) {
		const params = JSON.stringify(event.toolCall.parameters);
		const display = params.length > 60 ? `${params.slice(0, 60)}...` : params;
		console.log(`  ${DIM}params: ${display}${RESET}`);
	}

	console.log(`  ${DIM}│${RESET}`);
	console.log(`  ${DIM}├─${RESET} Policy evaluation`);
	const rule = event.decision.matchedRule?.name ?? "implicit deny";
	console.log(`  ${DIM}│  Rule: ${rule}${RESET}`);
	console.log(`  ${DIM}│${RESET}`);
	console.log(`  ${color}${BOLD}└─ ${verdict}${RESET} ${DIM}${event.decision.reason}${RESET}`);
}

export function runTrace(
	dbPath: string,
	runId: string | undefined,
	options: { latest?: boolean } = {},
): void {
	const store = new AuditStore(dbPath);

	try {
		let resolvedRunId = runId;

		if (options.latest || !resolvedRunId) {
			const runs = store.listRuns();
			if (runs.length === 0) {
				console.error("No runs found in database.");
				process.exit(1);
			}
			resolvedRunId = runs[0].runId;
			if (!runId) {
				console.log(`Using latest run: ${resolvedRunId}\n`);
			}
		}

		const result = replayRun(store, resolvedRunId!);
		if (!result) {
			console.error(`Run not found: ${resolvedRunId}`);
			process.exit(1);
		}

		const ctx = result.runContext;

		// Header
		console.log(`\n${CYAN}${BOLD}${"─".repeat(56)}${RESET}`);
		console.log(`${CYAN}${BOLD} Security Trace${RESET}`);
		console.log(`${CYAN}${BOLD}${"─".repeat(56)}${RESET}`);
		console.log(`  ${DIM}Run:${RESET}       ${ctx.runId}`);
		console.log(`  ${DIM}Principal:${RESET} ${ctx.principalId}`);
		console.log(`  ${DIM}Started:${RESET}   ${ctx.startedAt}`);
		console.log("");

		// Trace start
		console.log(`  ${CYAN}${BOLD}●${RESET} ${BOLD}Session start${RESET}`);

		// Render each event as a trace node
		for (const event of result.events) {
			printTraceEvent(event);
		}

		// Trace end
		console.log(`  ${DIM}│${RESET}`);
		if (ctx.endedAt) {
			console.log(
				`  ${CYAN}${BOLD}●${RESET} ${BOLD}Session end${RESET} ${DIM}${formatTimestamp(ctx.endedAt)}${RESET}`,
			);
		}

		// Summary
		const counts = { allow: 0, deny: 0, quarantine: 0 };
		for (const e of result.events) {
			if (e.toolCall.toolClass === "_system") counts.quarantine++;
			else if (e.decision.verdict === "allow") counts.allow++;
			else counts.deny++;
		}

		console.log("");
		console.log(
			`  ${GREEN}${counts.allow} allowed${RESET}  ${RED}${counts.deny} denied${RESET}  ${MAGENTA}${counts.quarantine} quarantine${RESET}`,
		);
		const integrityColor = result.integrity.valid ? GREEN : RED;
		const integrityLabel = result.integrity.valid ? "VALID" : "BROKEN";
		console.log(`  Hash chain: ${integrityColor}${BOLD}${integrityLabel}${RESET}`);
		console.log(`${CYAN}${BOLD}${"─".repeat(56)}${RESET}\n`);
	} finally {
		store.close();
	}
}
