import { readTrace, replayTrace } from "@arikernel/runtime";
import type { ReplayTrace, TraceReplayResult } from "@arikernel/runtime";

const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const CYAN = "\x1b[36m";
const MAGENTA = "\x1b[35m";
const RESET = "\x1b[0m";

export interface ReplayTraceOptions {
	policy?: string;
	preset?: string;
	json?: boolean;
	verbose?: boolean;
	timeline?: boolean;
	summary?: boolean;
	graph?: boolean;
}

export async function runReplayTrace(
	tracePath: string,
	options: ReplayTraceOptions = {},
): Promise<void> {
	let trace: ReplayTrace;
	try {
		trace = readTrace(tracePath);
	} catch (err) {
		console.error(`Failed to read trace file: ${tracePath}`);
		console.error(err instanceof Error ? err.message : String(err));
		process.exit(1);
	}

	console.log(`\n${CYAN}${BOLD}${"─".repeat(56)}${RESET}`);
	console.log(`${CYAN}${BOLD} Deterministic Attack Replay${RESET}`);
	console.log(`${CYAN}${BOLD}${"─".repeat(56)}${RESET}`);
	console.log(`  ${DIM}Trace:${RESET}     ${tracePath}`);
	console.log(`  ${DIM}Version:${RESET}   ${trace.traceVersion}`);
	console.log(`  ${DIM}Run ID:${RESET}    ${trace.runId}`);
	console.log(`  ${DIM}Started:${RESET}   ${trace.timestampStarted}`);
	if (trace.metadata.description) {
		console.log(`  ${DIM}Scenario:${RESET}  ${trace.metadata.description}`);
	}
	if (trace.metadata.preset) {
		console.log(`  ${DIM}Preset:${RESET}    ${trace.metadata.preset}`);
	}
	if (options.policy) {
		console.log(`  ${YELLOW}${DIM}Policy override:${RESET} ${options.policy}`);
	}
	if (options.preset) {
		console.log(`  ${YELLOW}${DIM}Preset override:${RESET} ${options.preset}`);
	}
	console.log(`${CYAN}${BOLD}${"─".repeat(56)}${RESET}\n`);

	// Build replay options
	const replayOptions: Record<string, unknown> = {};
	if (options.policy) {
		try {
			const { PolicyEngine } = require("@arikernel/policy-engine");
			const engine = new PolicyEngine(options.policy);
			// PolicyEngine loads and validates — we just need the path for the firewall
			replayOptions.policies = options.policy;
		} catch {
			// Pass policy path directly; will be resolved by replay engine
		}
	}
	if (options.preset) {
		replayOptions.preset = options.preset;
	}

	const result = await replayTrace(trace, replayOptions);

	if (options.json) {
		console.log(JSON.stringify(result.summary, null, 2));
		return;
	}

	// Print event-by-event comparison
	if (options.verbose) {
		for (const event of result.replayedEvents) {
			const origVerdict = event.originalDecision.verdict.toUpperCase();
			const replayVerdict = event.replayedDecision.verdict.toUpperCase();
			const matchIcon = event.matched ? `${GREEN}✓${RESET}` : `${RED}✗${RESET}`;
			const origColor = event.originalDecision.verdict === "allow" ? GREEN : RED;
			const replayColor = event.replayedDecision.verdict === "allow" ? GREEN : RED;

			console.log(
				`  ${DIM}#${event.sequence}${RESET} ${matchIcon} ` +
					`${event.request.toolClass}.${event.request.action}  ` +
					`${origColor}${origVerdict}${RESET} → ${replayColor}${replayVerdict}${RESET}`,
			);
			if (!event.matched) {
				console.log(`     ${RED}Original: ${event.originalDecision.reason}${RESET}`);
				console.log(`     ${RED}Replayed: ${event.replayedDecision.reason}${RESET}`);
			}
		}
		console.log("");
	}

	// Print mismatches
	if (result.mismatches.length > 0) {
		console.log(`  ${RED}${BOLD}Mismatches:${RESET}`);
		for (const m of result.mismatches) {
			console.log(
				`    ${RED}Event #${m.sequence}: ${m.field} changed from '${m.original}' to '${m.replayed}'${RESET}`,
			);
		}
		console.log("");
	}

	// Print summary
	console.log(`${CYAN}${BOLD}${"─".repeat(56)}${RESET}`);
	console.log(`${BOLD} Replay Summary${RESET}\n`);
	const qBlocked = trace.events.filter(
		(e) => e.capabilityGranted === false && e.decision.verdict === "deny",
	).length;
	const denied = result.summary.denied - qBlocked;
	console.log(`  Total events:       ${BOLD}${result.summary.totalEvents}${RESET}`);
	console.log(`  Allowed:            ${GREEN}${result.summary.allowed}${RESET}`);
	console.log(`  Denied:             ${RED}${denied}${RESET}`);
	if (qBlocked > 0) {
		console.log(`  Quarantine-blocked: ${MAGENTA}${qBlocked}${RESET}`);
	}
	console.log(
		`  Decisions matched:  ${result.summary.mismatched === 0 ? GREEN : RED}${result.summary.matched}/${result.summary.totalEvents}${RESET}`,
	);

	if (result.summary.originalQuarantined || result.summary.replayQuarantined) {
		const qMatch = result.quarantineMatched;
		console.log(
			`  Quarantine (orig):  ${result.summary.originalQuarantined ? `${MAGENTA}YES${RESET}` : "no"}`,
		);
		console.log(
			`  Quarantine (replay):${result.summary.replayQuarantined ? `${MAGENTA}YES${RESET}` : "no"}`,
		);
		console.log(`  Quarantine match:   ${qMatch ? `${GREEN}YES${RESET}` : `${RED}NO${RESET}`}`);
	}

	const allGood = result.allMatched && result.quarantineMatched;
	console.log("");
	console.log(
		`  Replay result:      ${allGood ? `${GREEN}${BOLD}DETERMINISTIC${RESET}` : `${RED}${BOLD}DIVERGED${RESET}`}`,
	);
	console.log(`${CYAN}${BOLD}${"─".repeat(56)}${RESET}\n`);

	// Timeline view
	if (options.timeline) {
		printTimeline(trace);
	}

	// Summary view
	if (options.summary) {
		printSummaryView(trace);
	}

	// Graph view
	if (options.graph) {
		printGraph(trace);
	}
}

function printTimeline(trace: ReplayTrace): void {
	const BAR = "\u2501";
	const startTime = new Date(trace.timestampStarted).getTime();
	const relativeTime = (iso: string) => {
		const delta = new Date(iso).getTime() - startTime;
		return `${(delta / 1000).toFixed(3)}s`;
	};

	console.log(`${CYAN}${BOLD}${BAR.repeat(56)}${RESET}`);
	console.log(`${CYAN}${BOLD} ARI KERNEL  ATTACK TIMELINE${RESET}`);
	console.log(`${CYAN}${BOLD}${BAR.repeat(56)}${RESET}\n`);

	// Show scenario if available
	if (trace.metadata.description) {
		console.log(`  ${DIM}Scenario: ${trace.metadata.description}${RESET}\n`);
	}

	const principal = trace.metadata.principal ?? "unknown";

	for (const event of trace.events) {
		const time = relativeTime(event.timestamp);
		const step = `${DIM}#${event.sequence}${RESET}`;
		const tool = `${event.request.toolClass}.${event.request.action}`;
		const target = (event.request.parameters.url ?? event.request.parameters.path ?? "") as string;
		const taintSources = event.request.taintLabels?.map((t) => t.source) ?? [];
		const taintStr =
			taintSources.length > 0 ? `${YELLOW}taint:[${taintSources.join(",")}]${RESET}` : "";
		const rule = event.decision.matchedRule
			? `${DIM}rule:${event.decision.matchedRule}${RESET}`
			: "";

		if (event.decision.verdict === "allow") {
			console.log(
				`  ${time}  ${step}  ${GREEN}\u2713 ALLOWED${RESET}  ${tool} ${DIM}${target}${RESET}`,
			);
		} else {
			const label = event.capabilityGranted === false ? "BLOCKED" : "DENIED";
			console.log(
				`  ${time}  ${step}  ${RED}\u2717 ${label}${RESET}   ${tool} ${DIM}${target}${RESET}`,
			);
			console.log(`${" ".repeat(28)}${DIM}${event.decision.reason}${RESET}`);
		}

		// Print metadata line (taint, principal, rule) if any are present
		const meta = [taintStr, `${DIM}principal:${principal}${RESET}`, rule]
			.filter(Boolean)
			.join("  ");
		if (meta) {
			console.log(`${" ".repeat(28)}${meta}`);
		}
		console.log();
	}

	// Insert quarantine entries
	if (trace.quarantines.length > 0) {
		for (const q of trace.quarantines) {
			const time = relativeTime(q.timestamp);
			const rule = q.ruleId ?? "behavioral detection";
			console.log(
				`  ${time}       ${MAGENTA}\ud83d\udd12 QUARANTINE${RESET}  Rule: ${BOLD}${rule}${RESET}`,
			);
			console.log(`${" ".repeat(28)}${DIM}${q.reason}${RESET}`);
			console.log();
		}
	} else if (trace.outcome.quarantined) {
		const lastDenied = [...trace.events]
			.reverse()
			.find((e) => e.decision.verdict === "deny" && e.capabilityGranted !== false);
		if (lastDenied) {
			const time = relativeTime(lastDenied.timestamp);
			console.log(`  ${time}       ${MAGENTA}\ud83d\udd12 QUARANTINE ACTIVATED${RESET}`);
			console.log(
				`${" ".repeat(28)}${DIM}Run locked to read-only after behavioral rule match${RESET}`,
			);
			console.log();
		}
	}

	// Result
	const contained = trace.outcome.quarantined;
	console.log(`${CYAN}${BOLD}${BAR.repeat(56)}${RESET}`);
	console.log(
		`${BOLD}  Result: ${contained ? `${RED}ATTACK CONTAINED${RESET}` : `${GREEN}NO ATTACK DETECTED${RESET}`}${RESET}`,
	);
	console.log(`${CYAN}${BOLD}${BAR.repeat(56)}${RESET}\n`);
}

function printSummaryView(trace: ReplayTrace): void {
	const BAR = "\u2501";
	console.log(`${CYAN}${BOLD}${BAR.repeat(56)}${RESET}`);
	console.log(`${CYAN}${BOLD} TRACE SUMMARY${RESET}`);
	console.log(`${CYAN}${BOLD}${BAR.repeat(56)}${RESET}\n`);

	if (trace.metadata.description) {
		console.log(`  ${DIM}Scenario:${RESET}  ${trace.metadata.description}`);
	}
	if (trace.metadata.principal) {
		console.log(`  ${DIM}Principal:${RESET} ${trace.metadata.principal}`);
	}
	if (trace.metadata.preset) {
		console.log(`  ${DIM}Preset:${RESET}    ${trace.metadata.preset}`);
	}
	const duration =
		new Date(trace.timestampCompleted).getTime() - new Date(trace.timestampStarted).getTime();
	console.log(`  ${DIM}Duration:${RESET}  ${duration}ms`);
	console.log();

	// Event summary table
	console.log(`  ${BOLD}Events:${RESET}`);
	for (const event of trace.events) {
		const tool = `${event.request.toolClass}.${event.request.action}`;
		const target = (event.request.parameters.url ?? event.request.parameters.path ?? "") as string;
		const short = target.length > 40 ? `${target.slice(0, 37)}...` : target;
		const verdictColor = event.decision.verdict === "allow" ? GREEN : RED;
		const verdict = event.decision.verdict.toUpperCase();
		const taint = (event.request.taintLabels?.length ?? 0) > 0 ? ` ${YELLOW}[tainted]${RESET}` : "";
		console.log(
			`    ${event.sequence + 1}. ${tool} ${DIM}${short}${RESET} \u2192 ${verdictColor}${verdict}${RESET}${taint}`,
		);
	}
	console.log();

	// Counters
	const c = trace.outcome.finalCounters;
	console.log(`  ${BOLD}Counters:${RESET}`);
	console.log(`    Denied actions:          ${c.deniedActions}`);
	console.log(`    Capability requests:     ${c.capabilityRequests}`);
	console.log(`    Denied capabilities:     ${c.deniedCapabilityRequests}`);
	console.log(`    Egress attempts:         ${c.externalEgressAttempts}`);
	console.log(`    Sensitive file reads:    ${c.sensitiveFileReadAttempts}`);
	console.log();

	// Verdict
	const o = trace.outcome;
	console.log(
		`  ${BOLD}Verdict:${RESET}  ${GREEN}${o.allowed} allowed${RESET}, ${RED}${o.denied} denied${RESET}` +
			`${o.quarantined ? `, ${MAGENTA}quarantined${RESET}` : ""}`,
	);
	console.log(`${CYAN}${BOLD}${BAR.repeat(56)}${RESET}\n`);
}

function printGraph(trace: ReplayTrace): void {
	const BAR = "\u2501";
	console.log(`${CYAN}${BOLD}${BAR.repeat(56)}${RESET}`);
	console.log(`${CYAN}${BOLD} ATTACK SEQUENCE GRAPH${RESET}`);
	console.log(`${CYAN}${BOLD}${BAR.repeat(56)}${RESET}\n`);

	if (trace.events.length === 0) {
		console.log(`  ${DIM}(no events)${RESET}\n`);
		return;
	}

	// Build nodes
	const nodes: Array<{ label: string; verdict: string; color: string }> = [];
	for (const event of trace.events) {
		const tool = `${event.request.toolClass}.${event.request.action}`;
		const target = (event.request.parameters.url ?? event.request.parameters.path ?? "") as string;
		const short = target.length > 30 ? `${target.slice(0, 27)}...` : target;
		const verdictColor = event.decision.verdict === "allow" ? GREEN : RED;
		const verdict = event.decision.verdict.toUpperCase();
		nodes.push({ label: `${tool} ${short}`, verdict, color: verdictColor });
	}

	// Render as vertical ASCII flowchart
	for (let i = 0; i < nodes.length; i++) {
		const node = nodes[i];
		const stepNum = `${DIM}#${i}${RESET}`;
		const box = `[${node.color}${node.verdict.padEnd(7)}${RESET}]`;
		console.log(`  ${stepNum}  ${box}  ${node.label}`);

		if (i < nodes.length - 1) {
			const nextColor = nodes[i + 1].color;
			console.log(`             ${nextColor}\u2502${RESET}`);
			console.log(`             ${nextColor}\u2514\u2500\u2500\u25b6${RESET}`);
		}
	}

	// Quarantine marker
	if (trace.outcome.quarantined) {
		console.log(`             ${RED}\u2502${RESET}`);
		console.log(
			`       ${MAGENTA}${BOLD}\ud83d\udd12 QUARANTINE${RESET} ${DIM}run locked to read-only${RESET}`,
		);
	}

	console.log();
	console.log(`${CYAN}${BOLD}${BAR.repeat(56)}${RESET}\n`);
}
