import type { Capability, PolicyRule, PresetId } from '@arikernel/core';
import { getPreset, DEFAULT_CAPABILITIES, DEFAULT_POLICIES } from '@arikernel/core';
import { Firewall } from './firewall.js';
import type { FirewallHooks } from './hooks.js';
import type { RunStatePolicy } from './run-state.js';
import { classifyScope, type ScopeResult } from './autoscope.js';

export interface KernelAllow {
	httpGet?: boolean;
	httpPost?: boolean;
	fileRead?: string[] | boolean;
	fileWrite?: string[] | boolean;
	shell?: boolean;
	database?: boolean;
}

export interface KernelOptions {
	preset?: PresetId;
	autoScope?: boolean;
	allow?: KernelAllow;
	principal?: string;
	auditLog?: string;
	hooks?: FirewallHooks;
	runStatePolicy?: RunStatePolicy;
}

export interface Kernel {
	readonly preset: PresetId | 'custom' | 'default';
	readonly autoScope: boolean;
	selectScope(task: string): ScopeResult;
	createFirewall(overrides?: { principal?: string; auditLog?: string }): Firewall;
}

function allowToCapabilitiesAndPolicies(allow: KernelAllow): {
	capabilities: Capability[];
	policies: PolicyRule[];
} {
	const capabilities: Capability[] = [];
	const policies: PolicyRule[] = [];

	if (allow.httpGet !== false) {
		capabilities.push({
			toolClass: 'http',
			actions: ['get'],
			constraints: { allowedHosts: ['*'] },
		});
		policies.push({
			id: 'allow-http-get',
			name: 'Allow HTTP GET',
			priority: 100,
			match: { toolClass: 'http', action: 'get' },
			decision: 'allow',
			reason: 'HTTP GET allowed',
		});
	}

	if (allow.httpPost) {
		capabilities.push({
			toolClass: 'http',
			actions: ['post'],
			constraints: { allowedHosts: ['*'] },
		});
		policies.push({
			id: 'allow-http-post',
			name: 'Allow HTTP POST',
			priority: 100,
			match: { toolClass: 'http', action: 'post' },
			decision: 'allow',
			reason: 'HTTP POST allowed',
		});
	} else {
		policies.push({
			id: 'deny-http-write',
			name: 'Deny HTTP writes',
			priority: 20,
			match: { toolClass: 'http', action: ['post', 'put', 'patch', 'delete'] },
			decision: 'deny',
			reason: 'Outbound HTTP writes are blocked',
		});
	}

	if (allow.fileRead !== false) {
		const paths = Array.isArray(allow.fileRead) ? allow.fileRead : ['./data/**', './docs/**', './workspace/**'];
		capabilities.push({
			toolClass: 'file',
			actions: ['read'],
			constraints: { allowedPaths: paths },
		});
		policies.push({
			id: 'allow-file-read',
			name: 'Allow file reads',
			priority: 100,
			match: { toolClass: 'file', action: 'read' },
			decision: 'allow',
			reason: 'File reads allowed (grant constraints enforce path limits)',
		});
	}

	if (allow.fileWrite) {
		const paths = Array.isArray(allow.fileWrite) ? allow.fileWrite : ['./**'];
		capabilities.push({
			toolClass: 'file',
			actions: ['write'],
			constraints: { allowedPaths: paths },
		});
		policies.push({
			id: 'allow-file-write',
			name: 'Allow file writes',
			priority: 100,
			match: { toolClass: 'file', action: 'write' },
			decision: 'allow',
			reason: 'File writes allowed (grant constraints enforce path limits)',
		});
	} else {
		policies.push({
			id: 'deny-file-write',
			name: 'Deny file writes',
			priority: 20,
			match: { toolClass: 'file', action: 'write' },
			decision: 'deny',
			reason: 'File writes are blocked',
		});
	}

	if (allow.shell) {
		capabilities.push({ toolClass: 'shell', actions: ['exec'] });
		policies.push({
			id: 'approve-shell',
			name: 'Shell requires approval',
			priority: 50,
			match: { toolClass: 'shell' },
			decision: 'require-approval',
			reason: 'Shell commands require approval',
		});
	} else {
		policies.push({
			id: 'deny-shell',
			name: 'Deny shell',
			priority: 10,
			match: { toolClass: 'shell' },
			decision: 'deny',
			reason: 'Shell execution is blocked',
		});
	}

	if (allow.database) {
		capabilities.push({ toolClass: 'database', actions: ['query'] });
		policies.push({
			id: 'allow-db-query',
			name: 'Allow DB queries',
			priority: 100,
			match: { toolClass: 'database', action: 'query' },
			decision: 'allow',
			reason: 'Database queries allowed',
		});
	}

	return { capabilities, policies };
}

function resolveConfig(options: KernelOptions): {
	capabilities: Capability[];
	policies: PolicyRule[];
	resolvedPreset: PresetId | 'custom' | 'default';
} {
	// Explicit allow overrides
	if (options.allow) {
		const { capabilities, policies } = allowToCapabilitiesAndPolicies(options.allow);
		return { capabilities, policies, resolvedPreset: 'custom' };
	}

	// Named preset
	if (options.preset) {
		const preset = getPreset(options.preset);
		return {
			capabilities: preset.capabilities,
			policies: preset.policies,
			resolvedPreset: options.preset,
		};
	}

	// Zero-config defaults
	return {
		capabilities: DEFAULT_CAPABILITIES,
		policies: DEFAULT_POLICIES,
		resolvedPreset: 'default',
	};
}

export function createKernel(options: KernelOptions = {}): Kernel {
	const { capabilities, policies, resolvedPreset } = resolveConfig(options);
	const principalName = options.principal ?? 'agent';
	const auditLog = options.auditLog;
	const hooks = options.hooks;
	const runStatePolicy = options.runStatePolicy ?? {
		maxDeniedSensitiveActions: 10,
		behavioralRules: true,
	};
	const isAutoScope = options.autoScope ?? false;

	// Mutable state for AutoScope — starts with resolved config
	let currentCapabilities = capabilities;
	let currentPolicies = policies;
	let currentPreset = resolvedPreset;

	return {
		get preset() {
			return currentPreset;
		},

		get autoScope() {
			return isAutoScope;
		},

		selectScope(task: string): ScopeResult {
			const result = classifyScope(task);
			if (isAutoScope && result.confidence > 0) {
				const preset = getPreset(result.preset);
				currentCapabilities = preset.capabilities;
				currentPolicies = preset.policies;
				currentPreset = result.preset;
			}
			return result;
		},

		createFirewall(overrides?: { principal?: string; auditLog?: string }): Firewall {
			return new Firewall({
				principal: {
					name: overrides?.principal ?? principalName,
					capabilities: currentCapabilities,
				},
				policies: currentPolicies,
				auditLog: overrides?.auditLog ?? auditLog,
				hooks,
				runStatePolicy,
			});
		},
	};
}

/** Global default kernel instance (lazy). */
let _defaultKernel: Kernel | null = null;

export function getDefaultKernel(): Kernel {
	if (!_defaultKernel) {
		_defaultKernel = createKernel();
	}
	return _defaultKernel;
}

/** Reset the global default kernel (for testing). */
export function resetDefaultKernel(): void {
	_defaultKernel = null;
}
