import { describe, it, expect, afterEach } from 'vitest';
import { ToolCallDeniedError } from '@arikernel/core';
import { createFirewall, type Firewall } from '@arikernel/runtime';
import { OpenClawAdapter } from '../src/openclaw.js';
import { resolve } from 'node:path';

const POLICY_PATH = resolve(import.meta.dirname, '..', '..', '..', 'policies', 'safe-defaults.yaml');

function makeFirewall(name: string): Firewall {
	return createFirewall({
		principal: {
			name,
			capabilities: [
				{ toolClass: 'http', actions: ['get'], constraints: { allowedHosts: ['api.example.com'] } },
				{ toolClass: 'file', actions: ['read'], constraints: { allowedPaths: ['./data/**'] } },
				{ toolClass: 'database', actions: ['query'] },
			],
		},
		policies: POLICY_PATH,
		auditLog: ':memory:',
	});
}

describe('OpenClawAdapter', () => {
	let fw: Firewall;
	afterEach(() => { fw?.close(); });

	it('executes allowed skill through firewall', async () => {
		fw = makeFirewall('openclaw-basic');
		const adapter = new OpenClawAdapter(fw);
		adapter.registerSkill('web_search', 'http', 'get', (args) => `Results for ${args.query}`);

		const result = await adapter.executeSkill('web_search', { query: 'hello', url: 'https://api.example.com/search' });
		expect(result).toBe('Results for hello');
	});

	it('blocks skill that violates constraints', async () => {
		fw = makeFirewall('openclaw-deny');
		const adapter = new OpenClawAdapter(fw);
		adapter.registerSkill('read_file', 'file', 'read', (args) => `Contents of ${args.path}`);

		await expect(
			adapter.executeSkill('read_file', { path: '~/.ssh/id_rsa' }),
		).rejects.toThrow(ToolCallDeniedError);
	});

	it('throws on unknown skill name', async () => {
		fw = makeFirewall('openclaw-unknown');
		const adapter = new OpenClawAdapter(fw);

		await expect(
			adapter.executeSkill('nonexistent', {}),
		).rejects.toThrow(/Unknown OpenClaw skill/);
	});

	it('supports fluent registration and lists skills', async () => {
		fw = makeFirewall('openclaw-fluent');
		const adapter = new OpenClawAdapter(fw)
			.registerSkill('search', 'http', 'get', () => 'a', { description: 'Search the web' })
			.registerSkill('read', 'file', 'read', () => 'b', { description: 'Read a file' })
			.registerSkill('query', 'database', 'query', () => 'c');

		expect(adapter.skillNames).toEqual(['search', 'read', 'query']);

		const info = adapter.getSkillInfo();
		expect(info).toHaveLength(3);
		expect(info[0]).toEqual({ name: 'search', description: 'Search the web', toolClass: 'http', action: 'get' });
		expect(info[2]).toEqual({ name: 'query', description: '', toolClass: 'database', action: 'query' });
	});

	it('triggers quarantine after repeated sensitive denials', async () => {
		fw = createFirewall({
			principal: {
				name: 'openclaw-quarantine',
				capabilities: [
					{ toolClass: 'file', actions: ['read'], constraints: { allowedPaths: ['./data/**'] } },
				],
			},
			policies: POLICY_PATH,
			auditLog: ':memory:',
			runStatePolicy: { maxDeniedSensitiveActions: 2 },
		});

		const adapter = new OpenClawAdapter(fw);
		adapter.registerSkill('read_file', 'file', 'read', (args) => `data: ${args.path}`);

		for (const path of ['~/.ssh/id_rsa', '~/.aws/credentials', '/etc/shadow']) {
			try { await adapter.executeSkill('read_file', { path }); } catch {}
		}

		expect(fw.isRestricted).toBe(true);
	});

	it('handler never executes when call is denied', async () => {
		fw = makeFirewall('openclaw-no-exec');
		let handlerCalled = false;
		const adapter = new OpenClawAdapter(fw);
		adapter.registerSkill('read_file', 'file', 'read', () => { handlerCalled = true; });

		try {
			await adapter.executeSkill('read_file', { path: '~/.ssh/id_rsa' });
		} catch {}

		expect(handlerCalled).toBe(false);
	});
});
