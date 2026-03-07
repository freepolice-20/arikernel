import { readFileSync } from 'node:fs';
import { PolicyValidationError, policySetSchema, type PolicyRule } from '@agent-firewall/core';
import { parse as parseYaml } from 'yaml';

export function loadPolicyFile(filePath: string): PolicyRule[] {
	const content = readFileSync(filePath, 'utf-8');
	const raw = parseYaml(content);
	const result = policySetSchema.safeParse(raw);

	if (!result.success) {
		throw new PolicyValidationError(
			`Invalid policy file: ${filePath}`,
			result.error.errors,
		);
	}

	return result.data.rules;
}

export function loadPolicies(source: string | PolicyRule[]): PolicyRule[] {
	if (Array.isArray(source)) return source;
	return loadPolicyFile(source);
}
