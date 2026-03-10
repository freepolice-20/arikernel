import type {
	Capability,
	Decision,
	PolicyRule,
	TaintLabel,
	ToolCall,
} from '@arikernel/core';
import { now } from '@arikernel/core';
import { DEFAULT_RULES } from './defaults.js';
import { loadPolicies } from './loader.js';
import { matchesRule } from './matcher.js';

export class PolicyEngine {
	private rules: PolicyRule[] = [];

	constructor(policies?: string | PolicyRule[]) {
		this.rules = [...DEFAULT_RULES];
		if (policies) {
			const loaded = loadPolicies(policies);
			this.rules = [...this.rules, ...loaded];
		}
		this.rules.sort((a, b) => a.priority - b.priority);
	}

	evaluate(
		toolCall: ToolCall,
		taintLabels: TaintLabel[],
		capabilities: Capability[],
	): Decision {
		const timestamp = now();

		// Step 1: capability check
		const capability = capabilities.find((c) => c.toolClass === toolCall.toolClass);
		if (!capability) {
			return {
				verdict: 'deny',
				matchedRule: null,
				reason: `No capability grant for tool class: ${toolCall.toolClass}`,
				taintLabels,
				timestamp,
			};
		}

		// Step 2: action check within capability
		if (capability.actions && capability.actions.length > 0) {
			if (!capability.actions.includes(toolCall.action)) {
				return {
					verdict: 'deny',
					matchedRule: null,
					reason: `Action '${toolCall.action}' not allowed. Permitted: ${capability.actions.join(', ')}`,
					taintLabels,
					timestamp,
				};
			}
		}

		// Step 3: constraint check
		const constraintViolation = checkConstraints(toolCall, capability);
		if (constraintViolation) {
			return {
				verdict: 'deny',
				matchedRule: null,
				reason: constraintViolation,
				taintLabels,
				timestamp,
			};
		}

		// Step 4: policy rules (sorted by priority, first match wins)
		for (const rule of this.rules) {
			if (matchesRule(rule.match, toolCall, taintLabels)) {
				return {
					verdict: rule.decision,
					matchedRule: rule,
					reason: rule.reason,
					taintLabels,
					timestamp,
				};
			}
		}

		// Step 5: implicit deny (should not reach here since DENY_ALL is in rules)
		return {
			verdict: 'deny',
			matchedRule: null,
			reason: 'No matching policy (deny-by-default)',
			taintLabels,
			timestamp,
		};
	}

	getRules(): readonly PolicyRule[] {
		return this.rules;
	}
}

function checkConstraints(toolCall: ToolCall, capability: Capability): string | null {
	const constraints = capability.constraints;
	if (!constraints) return null;

	if (constraints.allowedHosts && toolCall.toolClass === 'http') {
		const url = String(toolCall.parameters.url ?? '');
		try {
			const hostname = new URL(url).hostname;
			if (!constraints.allowedHosts.includes('*') && !constraints.allowedHosts.includes(hostname)) {
				return `Host '${hostname}' not in allowed hosts: ${constraints.allowedHosts.join(', ')}`;
			}
		} catch {
			return `Invalid URL: ${url}`;
		}
	}

	if (constraints.allowedCommands && toolCall.toolClass === 'shell') {
		const command = String(toolCall.parameters.command ?? '');
		const binary = command.split(/\s+/)[0];
		if (!constraints.allowedCommands.includes(binary)) {
			return `Command '${binary}' not in allowed commands: ${constraints.allowedCommands.join(', ')}`;
		}
	}

	if (constraints.allowedPaths && toolCall.toolClass === 'file') {
		const path = String(toolCall.parameters.path ?? '');
		const allowed = constraints.allowedPaths.some((pattern) => {
			if (pattern.endsWith('/**')) {
				return path.startsWith(pattern.slice(0, -3));
			}
			return path === pattern;
		});
		if (!allowed) {
			return `Path '${path}' not in allowed paths: ${constraints.allowedPaths.join(', ')}`;
		}
	}

	return null;
}
