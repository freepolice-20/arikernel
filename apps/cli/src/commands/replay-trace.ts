import { readTrace, replayTrace } from '@arikernel/runtime';
import type { ReplayTrace, TraceReplayResult } from '@arikernel/runtime';

const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const MAGENTA = '\x1b[35m';
const RESET = '\x1b[0m';

export interface ReplayTraceOptions {
	policy?: string;
	preset?: string;
	json?: boolean;
	verbose?: boolean;
	timeline?: boolean;
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

	console.log(`\n${CYAN}${BOLD}${'─'.repeat(56)}${RESET}`);
	console.log(`${CYAN}${BOLD} Deterministic Attack Replay${RESET}`);
	console.log(`${CYAN}${BOLD}${'─'.repeat(56)}${RESET}`);
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
	console.log(`${CYAN}${BOLD}${'─'.repeat(56)}${RESET}\n`);

	// Build replay options
	const replayOptions: any = {};
	if (options.policy) {
		try {
			const { PolicyEngine } = require('@arikernel/policy-engine');
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
			const origColor = event.originalDecision.verdict === 'allow' ? GREEN : RED;
			const replayColor = event.replayedDecision.verdict === 'allow' ? GREEN : RED;

			console.log(
				`  ${DIM}#${event.sequence}${RESET} ${matchIcon} ` +
				`${event.request.toolClass}.${event.request.action}  ` +
				`${origColor}${origVerdict}${RESET} → ${replayColor}${replayVerdict}${RESET}`
			);
			if (!event.matched) {
				console.log(`     ${RED}Original: ${event.originalDecision.reason}${RESET}`);
				console.log(`     ${RED}Replayed: ${event.replayedDecision.reason}${RESET}`);
			}
		}
		console.log('');
	}

	// Print mismatches
	if (result.mismatches.length > 0) {
		console.log(`  ${RED}${BOLD}Mismatches:${RESET}`);
		for (const m of result.mismatches) {
			console.log(`    ${RED}Event #${m.sequence}: ${m.field} changed from '${m.original}' to '${m.replayed}'${RESET}`);
		}
		console.log('');
	}

	// Print summary
	console.log(`${CYAN}${BOLD}${'─'.repeat(56)}${RESET}`);
	console.log(`${BOLD} Replay Summary${RESET}\n`);
	const qBlocked = trace.events.filter((e) => e.capabilityGranted === false && e.decision.verdict === 'deny').length;
	const denied = result.summary.denied - qBlocked;
	console.log(`  Total events:       ${BOLD}${result.summary.totalEvents}${RESET}`);
	console.log(`  Allowed:            ${GREEN}${result.summary.allowed}${RESET}`);
	console.log(`  Denied:             ${RED}${denied}${RESET}`);
	if (qBlocked > 0) {
		console.log(`  Quarantine-blocked: ${MAGENTA}${qBlocked}${RESET}`);
	}
	console.log(`  Decisions matched:  ${result.summary.mismatched === 0 ? GREEN : RED}${result.summary.matched}/${result.summary.totalEvents}${RESET}`);

	if (result.summary.originalQuarantined || result.summary.replayQuarantined) {
		const qMatch = result.quarantineMatched;
		console.log(`  Quarantine (orig):  ${result.summary.originalQuarantined ? `${MAGENTA}YES${RESET}` : 'no'}`);
		console.log(`  Quarantine (replay):${result.summary.replayQuarantined ? `${MAGENTA}YES${RESET}` : 'no'}`);
		console.log(`  Quarantine match:   ${qMatch ? `${GREEN}YES${RESET}` : `${RED}NO${RESET}`}`);
	}

	const allGood = result.allMatched && result.quarantineMatched;
	console.log('');
	console.log(`  Replay result:      ${allGood ? `${GREEN}${BOLD}DETERMINISTIC${RESET}` : `${RED}${BOLD}DIVERGED${RESET}`}`);
	console.log(`${CYAN}${BOLD}${'─'.repeat(56)}${RESET}\n`);

	// Timeline view
	if (options.timeline) {
		printTimeline(trace);
	}
}

function printTimeline(trace: ReplayTrace): void {
	const BAR = '\u2501';
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

	// Build timeline entries from events and quarantines
	interface TimelineEntry {
		time: string;
		timestamp: string;
		label: string;
		detail: string;
		color: string;
		icon: string;
	}

	const entries: TimelineEntry[] = [];

	for (const event of trace.events) {
		const time = relativeTime(event.timestamp);
		const tool = `${event.request.toolClass}.${event.request.action}`;
		const target = event.request.parameters.url ?? event.request.parameters.path ?? '';

		if (event.decision.verdict === 'allow') {
			entries.push({
				time,
				timestamp: event.timestamp,
				label: 'ALLOWED',
				detail: `${tool}  ${DIM}${target}${RESET}`,
				color: GREEN,
				icon: '\u2713', // ✓
			});

			// Check if this event had web taint
			const hasTaint = event.request.taintLabels?.some((t) => t.source === 'web');
			if (hasTaint) {
				entries.push({
					time,
					timestamp: event.timestamp,
					label: 'DATA TAINTED',
					detail: `${DIM}source: web${RESET}`,
					color: YELLOW,
					icon: '\u26a0', // ⚠
				});
			}
		} else {
			entries.push({
				time,
				timestamp: event.timestamp,
				label: event.capabilityGranted === false ? 'BLOCKED' : 'DENIED',
				detail: `${tool}  ${DIM}${target}${RESET}\n${' '.repeat(16)}${DIM}${event.decision.reason}${RESET}`,
				color: RED,
				icon: '\u2717', // ✗
			});
		}
	}

	// Insert quarantine entries
	if (trace.quarantines.length > 0) {
		for (const q of trace.quarantines) {
			const time = relativeTime(q.timestamp);
			const rule = q.ruleId ?? 'behavioral detection';
			entries.push({
				time,
				timestamp: q.timestamp,
				label: 'QUARANTINE',
				detail: `Rule: ${BOLD}${rule}${RESET}\n${' '.repeat(16)}${DIM}${q.reason}${RESET}`,
				color: MAGENTA,
				icon: '\ud83d\udd12', // 🔒
			});
		}
	} else if (trace.outcome.quarantined) {
		// Synthesize quarantine entry: place it after the last non-blocked denied event
		const lastDenied = [...trace.events].reverse().find(
			(e) => e.decision.verdict === 'deny' && e.capabilityGranted !== false,
		);
		if (lastDenied) {
			const time = relativeTime(lastDenied.timestamp);
			entries.push({
				time,
				timestamp: lastDenied.timestamp,
				label: 'QUARANTINE ACTIVATED',
				detail: `${DIM}Run locked to read-only after behavioral rule match${RESET}`,
				color: MAGENTA,
				icon: '\ud83d\udd12', // 🔒
			});
		}
	}

	// Sort by timestamp
	entries.sort((a, b) => a.timestamp.localeCompare(b.timestamp));

	// Render
	for (const entry of entries) {
		const timeStr = entry.time.padStart(8);
		console.log(
			`  ${DIM}${timeStr}${RESET}  ${entry.color}${entry.icon} ${BOLD}${entry.label}${RESET}`,
		);
		console.log(`${' '.repeat(12)}  ${entry.detail}`);
		console.log();
	}

	// Result
	const contained = trace.outcome.quarantined;
	console.log(`${CYAN}${BOLD}${BAR.repeat(56)}${RESET}`);
	console.log(
		`${BOLD}  Result: ${contained ? `${RED}ATTACK CONTAINED${RESET}` : `${GREEN}NO ATTACK DETECTED${RESET}`}${RESET}`,
	);
	console.log(`${CYAN}${BOLD}${BAR.repeat(56)}${RESET}\n`);
}
