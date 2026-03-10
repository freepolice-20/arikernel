import type { AuditEvent, RunContext } from '@arikernel/core';
import type { AuditStore } from './store.js';
import { verifyChain } from './hash-chain.js';

export interface ReplayResult {
	runContext: RunContext;
	events: AuditEvent[];
	integrity: ReplayIntegrity;
}

export interface ReplayIntegrity {
	valid: boolean;
	brokenAt?: number;
	anchorValid?: boolean;
	sequenceValid?: boolean;
	sequenceError?: string;
}

export function replayRun(store: AuditStore, runId: string): ReplayResult | null {
	const runContext = store.getRunContext(runId);
	if (!runContext) return null;

	const events = store.queryRun(runId);

	const chainData = events.map((e) => ({
		hash: e.hash,
		previousHash: e.previousHash,
		data: JSON.stringify({ toolCall: e.toolCall, decision: e.decision, result: e.result }),
	}));

	const chainResult = verifyChain(chainData);

	const integrity: ReplayIntegrity = { ...chainResult };

	// Verify anchor: first event's previousHash must match the run's start_previous_hash
	if (runContext.startPreviousHash != null && events.length > 0) {
		integrity.anchorValid = events[0].previousHash === runContext.startPreviousHash;
		if (!integrity.anchorValid) {
			integrity.valid = false;
		}
	}

	// Verify sequence continuity: starts at 0, no gaps
	integrity.sequenceValid = true;
	for (let i = 0; i < events.length; i++) {
		if (events[i].sequence !== i) {
			integrity.sequenceValid = false;
			integrity.valid = false;
			integrity.sequenceError =
				`expected sequence ${i}, got ${events[i].sequence}`;
			break;
		}
	}

	return { runContext, events, integrity };
}

/**
 * Verify hash chain integrity across all runs in chronological order.
 * Returns per-run results plus an overall cross-run chain validity check.
 */
export function verifyDatabaseChain(
	store: AuditStore,
): { runs: Array<{ runId: string; integrity: ReplayIntegrity }>; valid: boolean } {
	const runs = store.listRuns().reverse(); // oldest first
	const results: Array<{ runId: string; integrity: ReplayIntegrity }> = [];
	let allValid = true;

	for (const run of runs) {
		const result = replayRun(store, run.runId);
		if (!result) {
			results.push({
				runId: run.runId,
				integrity: { valid: false, sequenceValid: false },
			});
			allValid = false;
			continue;
		}
		results.push({ runId: run.runId, integrity: result.integrity });
		if (!result.integrity.valid) {
			allValid = false;
		}
	}

	return { runs: results, valid: allValid };
}
