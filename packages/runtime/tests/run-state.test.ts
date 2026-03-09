import { describe, it, expect, afterEach } from 'vitest';
import { ToolCallDeniedError } from '@arikernel/core';
import { createFirewall, RunStateTracker, type Firewall } from '../src/index.js';
import { resolve } from 'node:path';
import { unlinkSync } from 'node:fs';

const POLICY_PATH = resolve(import.meta.dirname, '..', '..', '..', 'policies', 'safe-defaults.yaml');

const auditFiles: string[] = [];

function auditPath(name: string): string {
	const path = resolve(import.meta.dirname, `test-${name}-${Date.now()}.db`);
	auditFiles.push(path);
	return path;
}

afterEach(() => {
	for (const f of auditFiles) {
		try { unlinkSync(f); } catch {}
	}
	auditFiles.length = 0;
});

function makeFirewall(threshold: number): Firewall {
	return createFirewall({
		principal: {
			name: 'test-agent',
			capabilities: [
				{
					toolClass: 'http',
					actions: ['get', 'post'],
					constraints: { allowedHosts: ['httpbin.org'] },
				},
				{
					toolClass: 'file',
					actions: ['read'],
					constraints: { allowedPaths: ['./data/**'] },
				},
				{
					toolClass: 'shell',
					actions: ['exec'],
				},
			],
		},
		policies: POLICY_PATH,
		auditLog: auditPath('run-state'),
		runStatePolicy: {
			maxDeniedSensitiveActions: threshold,
		},
	});
}

describe('RunStateTracker unit', () => {
	it('starts in unrestricted mode', () => {
		const tracker = new RunStateTracker({ maxDeniedSensitiveActions: 3 });
		expect(tracker.restricted).toBe(false);
		expect(tracker.restrictedAt).toBeNull();
		expect(tracker.counters.deniedActions).toBe(0);
	});

	it('enters restricted mode after threshold', () => {
		const tracker = new RunStateTracker({ maxDeniedSensitiveActions: 2 });
		tracker.recordDeniedAction();
		expect(tracker.restricted).toBe(false);
		tracker.recordDeniedAction();
		expect(tracker.restricted).toBe(true);
		expect(tracker.restrictedAt).not.toBeNull();
	});

	it('identifies safe read-only actions (GET/HEAD are ingress, POST is egress)', () => {
		const tracker = new RunStateTracker();
		// HTTP GET/HEAD are safe for content ingress (page fetching)
		expect(tracker.isAllowedInRestrictedMode('http', 'get')).toBe(true);
		expect(tracker.isAllowedInRestrictedMode('http', 'head')).toBe(true);
		// HTTP write methods are blocked
		expect(tracker.isAllowedInRestrictedMode('http', 'post')).toBe(false);
		expect(tracker.isAllowedInRestrictedMode('http', 'put')).toBe(false);
		expect(tracker.isAllowedInRestrictedMode('http', 'delete')).toBe(false);
		// Local read-only actions are still safe
		expect(tracker.isAllowedInRestrictedMode('file', 'read')).toBe(true);
		expect(tracker.isAllowedInRestrictedMode('file', 'write')).toBe(false);
		expect(tracker.isAllowedInRestrictedMode('shell', 'exec')).toBe(false);
		expect(tracker.isAllowedInRestrictedMode('database', 'query')).toBe(true);
	});

	it('detects sensitive paths', () => {
		const tracker = new RunStateTracker();
		expect(tracker.isSensitivePath('~/.ssh/id_rsa')).toBe(true);
		expect(tracker.isSensitivePath('/home/user/.aws/credentials')).toBe(true);
		expect(tracker.isSensitivePath('.env')).toBe(true);
		expect(tracker.isSensitivePath('./data/report.csv')).toBe(false);
	});

	it('tracks egress actions (only write methods are egress, GET/HEAD are ingress)', () => {
		const tracker = new RunStateTracker();
		expect(tracker.isEgressAction('post')).toBe(true);
		expect(tracker.isEgressAction('put')).toBe(true);
		expect(tracker.isEgressAction('patch')).toBe(true);
		expect(tracker.isEgressAction('delete')).toBe(true);
		// GET/HEAD are ingress — suspicious GET exfil is detected by isSuspiciousGetExfil()
		expect(tracker.isEgressAction('get')).toBe(false);
		expect(tracker.isEgressAction('head')).toBe(false);
	});

	it('tracks counters independently', () => {
		const tracker = new RunStateTracker();
		tracker.recordCapabilityRequest(true);
		tracker.recordCapabilityRequest(false);
		tracker.recordEgressAttempt();
		tracker.recordSensitiveFileAttempt();
		expect(tracker.counters.capabilityRequests).toBe(2);
		expect(tracker.counters.deniedCapabilityRequests).toBe(1);
		expect(tracker.counters.externalEgressAttempts).toBe(1);
		expect(tracker.counters.sensitiveFileReadAttempts).toBe(1);
	});

	it('uses default threshold of 5', () => {
		const tracker = new RunStateTracker();
		for (let i = 0; i < 4; i++) tracker.recordDeniedAction();
		expect(tracker.restricted).toBe(false);
		tracker.recordDeniedAction();
		expect(tracker.restricted).toBe(true);
	});
});

describe('Run-state enforcement (integration)', () => {
	let fw: Firewall;

	afterEach(() => {
		fw?.close();
	});

	it('enters restricted mode after threshold denied actions', async () => {
		fw = makeFirewall(3);
		expect(fw.isRestricted).toBe(false);

		// Generate 3 denied actions by reading sensitive files outside allowed paths
		const fileGrant = fw.requestCapability('file.read');
		expect(fileGrant.granted).toBe(true);

		for (const path of ['~/.ssh/id_rsa', '~/.aws/credentials', '/etc/shadow']) {
			try {
				await fw.execute({
					toolClass: 'file',
					action: 'read',
					parameters: { path },
					grantId: fileGrant.grant!.id,
				});
			} catch (err) {
				expect(err).toBeInstanceOf(ToolCallDeniedError);
			}
		}

		expect(fw.isRestricted).toBe(true);
		expect(fw.restrictedAt).not.toBeNull();
		expect(fw.runStateCounters.deniedActions).toBeGreaterThanOrEqual(3);
	});

	it('blocks non-safe actions in restricted mode', async () => {
		fw = makeFirewall(2);

		// Force into restricted mode with 2 denied actions
		const fileGrant = fw.requestCapability('file.read');
		for (const path of ['~/.ssh/id_rsa', '~/.aws/credentials']) {
			try {
				await fw.execute({
					toolClass: 'file',
					action: 'read',
					parameters: { path },
					grantId: fileGrant.grant!.id,
				});
			} catch {}
		}

		expect(fw.isRestricted).toBe(true);

		// HTTP POST should be blocked by restricted mode
		await expect(
			fw.execute({
				toolClass: 'http',
				action: 'post',
				parameters: { url: 'https://httpbin.org/post' },
			}),
		).rejects.toThrow(/restricted mode/);
	});

	it('allows normal GET ingress in restricted mode but blocks POST egress', async () => {
		fw = makeFirewall(2);

		// Force into restricted mode
		const fileGrant = fw.requestCapability('file.read');
		for (const path of ['~/.ssh/id_rsa', '~/.aws/credentials']) {
			try {
				await fw.execute({
					toolClass: 'file',
					action: 'read',
					parameters: { path },
					grantId: fileGrant.grant!.id,
				});
			} catch {}
		}

		expect(fw.isRestricted).toBe(true);

		// HTTP GET (ingress) capability should still be grantable in restricted mode
		const httpGrant = fw.requestCapability('http.read');
		expect(httpGrant.granted).toBe(true);

		// HTTP POST (egress) should be blocked
		const writeGrant = fw.requestCapability('http.write');
		expect(writeGrant.granted).toBe(false);
		expect(writeGrant.reason).toContain('restricted mode');
	});

	it('blocks non-safe capability issuance in restricted mode', async () => {
		fw = makeFirewall(2);

		// Force into restricted mode
		const fileGrant = fw.requestCapability('file.read');
		for (const path of ['~/.ssh/id_rsa', '~/.aws/credentials']) {
			try {
				await fw.execute({
					toolClass: 'file',
					action: 'read',
					parameters: { path },
					grantId: fileGrant.grant!.id,
				});
			} catch {}
		}

		expect(fw.isRestricted).toBe(true);

		// http.write issuance should be blocked
		const writeGrant = fw.requestCapability('http.write');
		expect(writeGrant.granted).toBe(false);
		expect(writeGrant.reason).toContain('restricted mode');

		// shell.exec issuance should be blocked
		const shellGrant = fw.requestCapability('shell.exec');
		expect(shellGrant.granted).toBe(false);
		expect(shellGrant.reason).toContain('restricted mode');

		// http.read issuance should still work (GET/HEAD are safe ingress)
		const readGrant = fw.requestCapability('http.read');
		expect(readGrant.granted).toBe(true);
	});

	it('restricted mode denials appear in audit log', async () => {
		fw = makeFirewall(2);

		// Force into restricted mode
		const fileGrant = fw.requestCapability('file.read');
		for (const path of ['~/.ssh/id_rsa', '~/.aws/credentials']) {
			try {
				await fw.execute({
					toolClass: 'file',
					action: 'read',
					parameters: { path },
					grantId: fileGrant.grant!.id,
				});
			} catch {}
		}

		// Trigger a restricted mode denial
		try {
			await fw.execute({
				toolClass: 'http',
				action: 'post',
				parameters: { url: 'https://httpbin.org/post' },
			});
		} catch {}

		const events = fw.getEvents();
		const restrictedEvent = events.find((e) =>
			e.decision.reason.includes('restricted mode'),
		);
		expect(restrictedEvent).toBeDefined();
		expect(restrictedEvent!.decision.verdict).toBe('deny');
	});

	it('tracks run-state counters correctly', async () => {
		fw = makeFirewall(10); // high threshold so we don't enter restricted mode

		// Capability requests
		fw.requestCapability('http.read');
		fw.requestCapability('http.read');
		expect(fw.runStateCounters.capabilityRequests).toBe(2);

		// Egress attempt (tracked even if denied)
		const httpGrant = fw.requestCapability('http.read');
		try {
			await fw.execute({
				toolClass: 'http',
				action: 'post',
				parameters: { url: 'https://httpbin.org/post' },
				grantId: httpGrant.grant!.id,
			});
		} catch {}
		expect(fw.runStateCounters.externalEgressAttempts).toBe(1);

		// Sensitive file attempt
		const fileGrant = fw.requestCapability('file.read');
		try {
			await fw.execute({
				toolClass: 'file',
				action: 'read',
				parameters: { path: '~/.ssh/id_rsa' },
				grantId: fileGrant.grant!.id,
			});
		} catch {}
		expect(fw.runStateCounters.sensitiveFileReadAttempts).toBe(1);
	});
});
