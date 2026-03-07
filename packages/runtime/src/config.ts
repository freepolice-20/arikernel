import type { Capability, PolicyRule } from '@agent-firewall/core';
import { firewallConfigSchema } from '@agent-firewall/core';
import type { FirewallHooks } from './hooks.js';

export interface FirewallOptions {
	principal: {
		name: string;
		capabilities: Capability[];
	};
	policies: string | PolicyRule[];
	auditLog?: string;
	hooks?: FirewallHooks;
}

export function validateOptions(options: FirewallOptions): FirewallOptions {
	firewallConfigSchema.parse({
		principal: options.principal,
		policies: options.policies,
		auditLog: options.auditLog ?? './audit.db',
	});
	return options;
}
