import { describe, it, expect } from 'vitest';
import { aggregateMetrics } from '../src/metrics.js';
import type { ScenarioResult } from '../src/types.js';

function makeResult(overrides: Partial<ScenarioResult>): ScenarioResult {
	return {
		scenarioId: 'test',
		scenarioName: 'Test Scenario',
		attackClass: 'prompt_injection',
		blockedBy: null,
		wasQuarantined: false,
		sensitiveReadPrevented: null,
		exfiltrationPrevented: null,
		deniedCount: 0,
		allowedCount: 1,
		runId: 'run-1',
		auditDbPath: './test.db',
		durationMs: 10,
		outcomeNote: 'test',
		...overrides,
	};
}

describe('aggregateMetrics', () => {
	it('returns zeros for empty results', () => {
		const s = aggregateMetrics([]);
		expect(s.totalScenarios).toBe(0);
		expect(s.attacksBlocked).toBe(0);
		expect(s.attacksBlockedPct).toBe(0);
		expect(s.quarantinedRuns).toBe(0);
		expect(s.sensitiveReadsPreventedPct).toBe(0);
		expect(s.exfiltrationPreventedPct).toBe(0);
	});

	it('counts quarantined runs correctly', () => {
		const results = [
			makeResult({ wasQuarantined: true }),
			makeResult({ wasQuarantined: false }),
			makeResult({ wasQuarantined: true }),
		];
		const s = aggregateMetrics(results);
		expect(s.quarantinedRuns).toBe(2);
		expect(s.quarantinedRunsPct).toBe(67);
	});

	it('counts attacksBlocked: quarantine counts as blocked', () => {
		const results = [
			makeResult({ wasQuarantined: true }),
			makeResult({ wasQuarantined: false, exfiltrationPrevented: false }),
		];
		const s = aggregateMetrics(results);
		expect(s.attacksBlocked).toBe(1);
		expect(s.attacksBlockedPct).toBe(50);
	});

	it('counts attacksBlocked: exfil prevented counts as blocked', () => {
		const results = [
			makeResult({ exfiltrationPrevented: true }),
			makeResult({ exfiltrationPrevented: false }),
		];
		const s = aggregateMetrics(results);
		expect(s.attacksBlocked).toBe(1);
	});

	it('ignores null sensitiveReadPrevented in percentage', () => {
		const results = [
			makeResult({ sensitiveReadPrevented: null }),  // not applicable
			makeResult({ sensitiveReadPrevented: true }),
			makeResult({ sensitiveReadPrevented: false }),
		];
		const s = aggregateMetrics(results);
		// Only 2 scenarios have a sensitive read step; 1 prevented
		expect(s.sensitiveReadsPreventedPct).toBe(50);
	});

	it('reports 100% exfil prevented when all are blocked', () => {
		const results = [
			makeResult({ exfiltrationPrevented: true }),
			makeResult({ exfiltrationPrevented: true }),
			makeResult({ exfiltrationPrevented: true }),
		];
		const s = aggregateMetrics(results);
		expect(s.exfiltrationPreventedPct).toBe(100);
	});

	it('handles mixed null and non-null exfil correctly', () => {
		const results = [
			makeResult({ exfiltrationPrevented: null }),  // N/A
			makeResult({ exfiltrationPrevented: true }),
			makeResult({ exfiltrationPrevented: false }),
		];
		const s = aggregateMetrics(results);
		expect(s.exfiltrationPreventedPct).toBe(50);
	});
});
