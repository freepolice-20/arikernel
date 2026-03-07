import type { AuditEvent, RunContext } from '@agent-firewall/core';
import type { AuditStore } from './store.js';
import { verifyChain } from './hash-chain.js';

export interface ReplayResult {
	runContext: RunContext;
	events: AuditEvent[];
	integrity: { valid: boolean; brokenAt?: number };
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

	const integrity = verifyChain(chainData);

	return { runContext, events, integrity };
}
