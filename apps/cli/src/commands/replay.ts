import { AuditStore, replayRun } from '@agent-firewall/audit-log';
import { printAuditEvent, printRunHeader, printReplaySummary } from '../output.js';

export interface ReplayOptions {
	latest?: boolean;
	verbose?: boolean;
}

export function runReplay(dbPath: string, runId: string | undefined, options: ReplayOptions = {}): void {
	const store = new AuditStore(dbPath);

	try {
		let resolvedRunId = runId;

		if (options.latest || !resolvedRunId) {
			const runs = store.listRuns();
			if (runs.length === 0) {
				console.error('No runs found in database.');
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

		printRunHeader(result.runContext);

		for (const event of result.events) {
			printAuditEvent(event, options.verbose);
		}

		printReplaySummary(result.events, result.integrity.valid);
	} finally {
		store.close();
	}
}
