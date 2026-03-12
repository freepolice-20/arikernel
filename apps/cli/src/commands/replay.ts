import { AuditStore, replayRun } from "@arikernel/audit-log";
import { printAuditEvent, printReplaySummary, printRunHeader } from "../output.js";

export interface ReplayOptions {
	latest?: boolean;
	verbose?: boolean;
	step?: boolean;
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function runReplay(
	dbPath: string,
	runId: string | undefined,
	options: ReplayOptions = {},
): Promise<void> {
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

		if (!resolvedRunId) {
			console.error("No run ID resolved.");
			process.exit(1);
		}
		const result = replayRun(store, resolvedRunId);
		if (!result) {
			console.error(`Run not found: ${resolvedRunId}`);
			process.exit(1);
		}

		printRunHeader(result.runContext);

		if (options.step) {
			const DIM = "\x1b[2m";
			const RESET = "\x1b[0m";

			for (let i = 0; i < result.events.length; i++) {
				const event = result.events[i];
				console.log(`${DIM}[event ${i + 1}/${result.events.length}]${RESET}`);
				printAuditEvent(event, options.verbose);
				if (i < result.events.length - 1) {
					await sleep(800);
				}
			}
		} else {
			for (const event of result.events) {
				printAuditEvent(event, options.verbose);
			}
		}

		printReplaySummary(result.events, result.integrity.valid);
	} finally {
		store.close();
	}
}
