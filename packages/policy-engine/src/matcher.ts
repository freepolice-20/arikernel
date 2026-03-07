import type { PolicyMatch, TaintLabel, ToolCall } from '@agent-firewall/core';

export function matchesRule(match: PolicyMatch, toolCall: ToolCall, taintLabels: TaintLabel[]): boolean {
	if (!matchesToolClass(match.toolClass, toolCall.toolClass)) return false;
	if (!matchesAction(match.action, toolCall.action)) return false;
	if (!matchesPrincipal(match.principalId, toolCall.principalId)) return false;
	if (!matchesTaintSources(match.taintSources, taintLabels)) return false;
	if (!matchesParameters(match.parameters, toolCall.parameters)) return false;
	return true;
}

function matchesToolClass(
	expected: PolicyMatch['toolClass'],
	actual: string,
): boolean {
	if (expected === undefined) return true;
	if (Array.isArray(expected)) return expected.includes(actual as never);
	return expected === actual;
}

function matchesAction(
	expected: PolicyMatch['action'],
	actual: string,
): boolean {
	if (expected === undefined) return true;
	if (Array.isArray(expected)) return expected.includes(actual);
	return expected === actual;
}

function matchesPrincipal(expected: string | undefined, actual: string): boolean {
	if (expected === undefined) return true;
	return expected === actual;
}

function matchesTaintSources(
	expected: PolicyMatch['taintSources'],
	taintLabels: TaintLabel[],
): boolean {
	if (expected === undefined || expected.length === 0) return true;
	return expected.some((source) =>
		taintLabels.some((label) => label.source === source),
	);
}

function matchesParameters(
	matchers: PolicyMatch['parameters'],
	params: Record<string, unknown>,
): boolean {
	if (matchers === undefined) return true;

	for (const [key, matcher] of Object.entries(matchers)) {
		const value = String(params[key] ?? '');

		if (matcher.pattern) {
			const regex = new RegExp(matcher.pattern);
			if (!regex.test(value)) return false;
		}

		if (matcher.in) {
			if (!matcher.in.includes(value)) return false;
		}

		if (matcher.notIn) {
			if (matcher.notIn.includes(value)) return false;
		}
	}

	return true;
}
