import { describe, it, expect } from 'vitest';
import { createSecretPatternFilter } from '../src/output-filter.js';
import type { ToolCall, ToolResult } from '@arikernel/core';

function makeToolCall(): ToolCall {
	return {
		id: 'tc-1',
		runId: 'run-1',
		sequence: 0,
		timestamp: new Date().toISOString(),
		principalId: 'test',
		toolClass: 'http',
		action: 'get',
		parameters: {},
		taintLabels: [],
	};
}

function makeResult(data: unknown): ToolResult {
	return {
		callId: 'tc-1',
		success: true,
		data,
		taintLabels: [],
		durationMs: 10,
	};
}

describe('createSecretPatternFilter', () => {
	const filter = createSecretPatternFilter();
	const tc = makeToolCall();

	it('redacts AWS access keys', () => {
		const result = filter(tc, makeResult('key is AKIAIOSFODNN7EXAMPLE here'));
		expect(result.data).toBe('key is [REDACTED] here');
		expect(result.taintLabels).toHaveLength(1);
		expect(result.taintLabels[0].source).toBe('tool-output');
	});

	it('redacts private keys', () => {
		const result = filter(tc, makeResult('-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----'));
		expect(result.data).toContain('[REDACTED]');
		expect(result.data).not.toContain('BEGIN RSA PRIVATE KEY');
	});

	it('redacts GitHub tokens', () => {
		const result = filter(tc, makeResult('token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl'));
		expect(result.data).toContain('[REDACTED]');
		expect(result.data).not.toContain('ghp_');
	});

	it('redacts Bearer tokens', () => {
		const result = filter(tc, makeResult('Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig'));
		expect(result.data).toContain('[REDACTED]');
		expect(result.data).not.toContain('Bearer ey');
	});

	it('passes through clean strings unchanged', () => {
		const result = filter(tc, makeResult('Hello world, nothing secret here'));
		expect(result.data).toBe('Hello world, nothing secret here');
		expect(result.taintLabels).toHaveLength(0);
	});

	it('passes through non-string data unchanged', () => {
		const obj = { count: 42, items: ['a', 'b'] };
		const result = filter(tc, makeResult(obj));
		expect(result.data).toEqual(obj);
		expect(result.taintLabels).toHaveLength(0);
	});

	it('detects multiple secret types in one string', () => {
		const input = 'key=AKIAIOSFODNN7EXAMPLE token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl';
		const result = filter(tc, makeResult(input));
		expect(result.data).not.toContain('AKIA');
		expect(result.data).not.toContain('ghp_');
		expect(result.taintLabels[0].origin).toContain('redacted:');
		expect(result.taintLabels[0].origin).toContain('aws-access-key');
		expect(result.taintLabels[0].origin).toContain('github-token');
	});

	it('supports custom replacement string', () => {
		const customFilter = createSecretPatternFilter({ replacement: '***' });
		const result = customFilter(tc, makeResult('key AKIAIOSFODNN7EXAMPLE end'));
		expect(result.data).toContain('***');
	});

	it('supports custom patterns', () => {
		const customFilter = createSecretPatternFilter({
			patterns: [{ name: 'custom', regex: /SECRET_\w+/g }],
		});
		const result = customFilter(tc, makeResult('value is SECRET_ABC123 here'));
		expect(result.data).toBe('value is [REDACTED] here');
	});
});
