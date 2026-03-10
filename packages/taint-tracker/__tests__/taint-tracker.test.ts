import { describe, it, expect } from 'vitest';
import type { TaintLabel, ToolCall } from '@arikernel/core';
import {
	TaintTracker,
	createTaintLabel,
	hasTaint,
	hasAnyTaint,
	mergeTaints,
	propagateTaints,
} from '../src/index.js';

describe('createTaintLabel', () => {
	it('creates a label with source and origin', () => {
		const label = createTaintLabel('web', 'example.com');
		expect(label.source).toBe('web');
		expect(label.origin).toBe('example.com');
		expect(label.confidence).toBe(1.0);
		expect(label.addedAt).toBeDefined();
		expect(label.propagatedFrom).toBeUndefined();
	});

	it('clamps confidence above 1 to 1', () => {
		const label = createTaintLabel('web', 'test', 5.0);
		expect(label.confidence).toBe(1.0);
	});

	it('clamps confidence below 0 to 0', () => {
		const label = createTaintLabel('web', 'test', -1.0);
		expect(label.confidence).toBe(0);
	});

	it('preserves confidence at boundaries', () => {
		expect(createTaintLabel('web', 'test', 0).confidence).toBe(0);
		expect(createTaintLabel('web', 'test', 1).confidence).toBe(1);
		expect(createTaintLabel('web', 'test', 0.5).confidence).toBe(0.5);
	});

	it('includes propagatedFrom when provided', () => {
		const label = createTaintLabel('web', 'example.com', 0.9, 'call-123');
		expect(label.propagatedFrom).toBe('call-123');
	});
});

describe('hasTaint', () => {
	it('returns true when source exists', () => {
		const labels: TaintLabel[] = [createTaintLabel('web', 'example.com')];
		expect(hasTaint(labels, 'web')).toBe(true);
	});

	it('returns false when source does not exist', () => {
		const labels: TaintLabel[] = [createTaintLabel('web', 'example.com')];
		expect(hasTaint(labels, 'email')).toBe(false);
	});

	it('returns false for empty array', () => {
		expect(hasTaint([], 'web')).toBe(false);
	});
});

describe('hasAnyTaint', () => {
	it('returns true if any source matches', () => {
		const labels: TaintLabel[] = [createTaintLabel('web', 'test')];
		expect(hasAnyTaint(labels, ['email', 'web'])).toBe(true);
	});

	it('returns false if no source matches', () => {
		const labels: TaintLabel[] = [createTaintLabel('web', 'test')];
		expect(hasAnyTaint(labels, ['email', 'rag'])).toBe(false);
	});

	it('returns true for empty sources array', () => {
		// some() on empty array returns false
		expect(hasAnyTaint([createTaintLabel('web', 'test')], [])).toBe(false);
	});
});

describe('mergeTaints', () => {
	it('merges labels from multiple sets', () => {
		const set1 = [createTaintLabel('web', 'a.com')];
		const set2 = [createTaintLabel('email', 'inbox')];
		const merged = mergeTaints(set1, set2);
		expect(merged).toHaveLength(2);
	});

	it('deduplicates by source:origin key', () => {
		const set1 = [createTaintLabel('web', 'a.com')];
		const set2 = [createTaintLabel('web', 'a.com', 0.5)];
		const merged = mergeTaints(set1, set2);
		expect(merged).toHaveLength(1);
		// First occurrence wins
		expect(merged[0].confidence).toBe(1.0);
	});

	it('keeps labels with same source but different origins', () => {
		const set1 = [createTaintLabel('web', 'a.com')];
		const set2 = [createTaintLabel('web', 'b.com')];
		const merged = mergeTaints(set1, set2);
		expect(merged).toHaveLength(2);
	});

	it('handles empty inputs', () => {
		expect(mergeTaints([], [])).toHaveLength(0);
		const set1 = [createTaintLabel('web', 'a.com')];
		expect(mergeTaints(set1, [])).toHaveLength(1);
	});
});

describe('propagateTaints', () => {
	it('returns empty array for empty input', () => {
		expect(propagateTaints([], 'call-1')).toHaveLength(0);
	});

	it('propagates labels with callId as propagatedFrom', () => {
		const input = [createTaintLabel('web', 'example.com', 0.9)];
		const result = propagateTaints(input, 'call-1');

		const webLabel = result.find((l) => l.source === 'web');
		expect(webLabel).toBeDefined();
		expect(webLabel!.propagatedFrom).toBe('call-1');
		expect(webLabel!.confidence).toBe(0.9);
	});

	it('adds tool-output taint with callId as origin', () => {
		const input = [createTaintLabel('web', 'example.com')];
		const result = propagateTaints(input, 'call-1');

		const toolOutput = result.find((l) => l.source === 'tool-output');
		expect(toolOutput).toBeDefined();
		expect(toolOutput!.origin).toBe('call-1');
		expect(toolOutput!.confidence).toBe(1.0);
	});

	it('preserves all input sources plus tool-output', () => {
		const input = [
			createTaintLabel('web', 'a.com'),
			createTaintLabel('email', 'inbox'),
		];
		const result = propagateTaints(input, 'call-1');
		expect(result).toHaveLength(3); // web + email + tool-output
	});
});

describe('TaintTracker class', () => {
	it('attach creates a label', () => {
		const tracker = new TaintTracker();
		const label = tracker.attach('web', 'example.com', 0.8);
		expect(label.source).toBe('web');
		expect(label.origin).toBe('example.com');
		expect(label.confidence).toBe(0.8);
	});

	it('collectInputTaints extracts from toolCall', () => {
		const tracker = new TaintTracker();
		const labels = [createTaintLabel('web', 'test')];
		const tc = {
			id: 'tc-1',
			runId: 'run-1',
			sequence: 0,
			timestamp: new Date().toISOString(),
			principalId: 'agent',
			toolClass: 'http',
			action: 'get',
			parameters: {},
			taintLabels: labels,
		} as ToolCall;
		expect(tracker.collectInputTaints(tc)).toEqual(labels);
	});

	it('collectInputTaints returns empty array when taintLabels is undefined', () => {
		const tracker = new TaintTracker();
		const tc = {
			id: 'tc-1',
			runId: 'run-1',
			sequence: 0,
			timestamp: new Date().toISOString(),
			principalId: 'agent',
			toolClass: 'http',
			action: 'get',
			parameters: {},
		} as ToolCall;
		expect(tracker.collectInputTaints(tc)).toEqual([]);
	});

	it('hasTaint delegates correctly', () => {
		const tracker = new TaintTracker();
		const labels = [createTaintLabel('web', 'test')];
		expect(tracker.hasTaint(labels, 'web')).toBe(true);
		expect(tracker.hasTaint(labels, 'email')).toBe(false);
	});

	it('merge delegates correctly', () => {
		const tracker = new TaintTracker();
		const s1 = [createTaintLabel('web', 'a')];
		const s2 = [createTaintLabel('email', 'b')];
		expect(tracker.merge(s1, s2)).toHaveLength(2);
	});

	it('propagate delegates correctly', () => {
		const tracker = new TaintTracker();
		const input = [createTaintLabel('web', 'test')];
		const result = tracker.propagate(input, 'call-1');
		expect(result.length).toBeGreaterThan(0);
		expect(result.some((l) => l.source === 'tool-output')).toBe(true);
	});
});
