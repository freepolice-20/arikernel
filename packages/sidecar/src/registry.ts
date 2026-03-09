import { join } from 'node:path';
import { mkdirSync } from 'node:fs';
import { createFirewall, type Firewall } from '@arikernel/runtime';
import { HttpExecutor, FileExecutor, ShellExecutor, DatabaseExecutor, RetrievalExecutor } from '@arikernel/tool-executors';
import type { PolicyRule } from '@arikernel/core';
import type { RunStatePolicy } from '@arikernel/runtime';

const ALL_TOOL_CLASSES = ['http', 'file', 'shell', 'database', 'retrieval'] as const;

function buildCapabilities() {
	return ALL_TOOL_CLASSES.map((toolClass) => ({ toolClass }));
}

function attachExecutors(firewall: Firewall): void {
	firewall.registerExecutor(new HttpExecutor());
	firewall.registerExecutor(new FileExecutor());
	firewall.registerExecutor(new ShellExecutor());
	firewall.registerExecutor(new DatabaseExecutor());
	firewall.registerExecutor(new RetrievalExecutor());
}

/**
 * Manages one Firewall per principalId. Each principal gets its own run-state,
 * taint graph, and audit DB — enforcing quarantine and behavioral rules independently.
 */
export class PrincipalRegistry {
	private readonly firewalls = new Map<string, Firewall>();
	private readonly auditDir: string;
	private readonly policies: string | PolicyRule[];
	private readonly runStatePolicy?: RunStatePolicy;

	constructor(auditDir: string, policies: string | PolicyRule[], runStatePolicy?: RunStatePolicy) {
		mkdirSync(auditDir, { recursive: true });
		this.auditDir = auditDir;
		this.policies = policies;
		this.runStatePolicy = runStatePolicy;
	}

	getOrCreate(principalId: string): Firewall {
		const existing = this.firewalls.get(principalId);
		if (existing) return existing;

		const sanitized = principalId.replace(/[^a-zA-Z0-9_-]/g, '_');
		const auditLog = join(this.auditDir, `${sanitized}.db`);

		const firewall = createFirewall({
			principal: {
				name: principalId,
				capabilities: buildCapabilities(),
			},
			policies: this.policies,
			auditLog,
			runStatePolicy: this.runStatePolicy,
		});

		attachExecutors(firewall);
		this.firewalls.set(principalId, firewall);
		return firewall;
	}

	/** Check if a principal has an active firewall (without creating one). */
	has(principalId: string): boolean {
		return this.firewalls.has(principalId);
	}

	closeAll(): void {
		for (const fw of this.firewalls.values()) {
			try { fw.close(); } catch { /* ignore */ }
		}
		this.firewalls.clear();
	}
}
