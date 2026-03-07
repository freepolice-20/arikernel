import { AuditStore, replayRun } from '@agent-firewall/audit-log';
import { printAuditEvent, printReplaySummary } from '../output.js';

export function runReplay(dbPath: string, runId: string): void {
	const store = new AuditStore(dbPath);

	try {
		const result = replayRun(store, runId);
		if (!result) {
			console.error(`Run not found: ${runId}`);
			process.exit(1);
		}

		console.log(`Replaying run: ${runId}`);
		console.log(`Principal: ${result.runContext.principalId}`);
		console.log(`Started: ${result.runContext.startedAt}\n`);

		for (const event of result.events) {
			printAuditEvent(event);
		}

		printReplaySummary(result.events, result.integrity.valid);
	} finally {
		store.close();
	}
}
