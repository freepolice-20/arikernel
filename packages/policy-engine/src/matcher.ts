import type { PolicyMatch, TaintLabel, ToolCall } from "@arikernel/core";

/**
 * Maximum input length for regex evaluation. Inputs exceeding this limit
 * are treated as unsafe — the rule is force-matched to ensure deny rules
 * still fire. This prevents attacker-controlled input from causing
 * catastrophic backtracking in policy regex patterns.
 */
const MAX_REGEX_INPUT_LENGTH = 8192;

/**
 * Thrown when parameter matching cannot produce a trustworthy result.
 * The policy engine catches this and treats it as an unconditional deny,
 * ensuring that unsafe regex, oversized input, or invalid policy patterns
 * can never convert an intended deny rule into an allow.
 *
 * Why post-hoc wall-clock timing is NOT real ReDoS mitigation:
 * - JavaScript regex runs synchronously on the event loop; there is no
 *   mechanism to interrupt a running regex.test() call.
 * - performance.now() measured after completion tells you the damage
 *   already happened — the event loop was blocked.
 * - A catastrophic backtracking pattern can block for seconds or minutes,
 *   effectively DoS-ing the entire kernel process.
 *
 * Instead we use pre-evaluation safety checks:
 * 1. Input length bounds (MAX_REGEX_INPUT_LENGTH)
 * 2. Fail-closed on any error — UnsafeMatchError triggers unconditional deny
 */
export class UnsafeMatchError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "UnsafeMatchError";
	}
}

export function matchesRule(
	match: PolicyMatch,
	toolCall: ToolCall,
	taintLabels: TaintLabel[],
): boolean {
	if (!matchesToolClass(match.toolClass, toolCall.toolClass)) return false;
	if (!matchesAction(match.action, toolCall.action)) return false;
	if (!matchesPrincipal(match.principalId, toolCall.principalId)) return false;
	if (!matchesTaintSources(match.taintSources, taintLabels)) return false;
	// matchesParameters may throw UnsafeMatchError — callers must handle it
	if (!matchesParameters(match.parameters, toolCall.parameters)) return false;
	return true;
}

function matchesToolClass(expected: PolicyMatch["toolClass"], actual: string): boolean {
	if (expected === undefined) return true;
	if (Array.isArray(expected)) return expected.includes(actual as never);
	return expected === actual;
}

function matchesAction(expected: PolicyMatch["action"], actual: string): boolean {
	if (expected === undefined) return true;
	if (Array.isArray(expected)) return expected.includes(actual);
	return expected === actual;
}

function matchesPrincipal(expected: string | undefined, actual: string): boolean {
	if (expected === undefined) return true;
	return expected === actual;
}

function matchesTaintSources(
	expected: PolicyMatch["taintSources"],
	taintLabels: TaintLabel[],
): boolean {
	if (expected === undefined || expected.length === 0) return true;
	return expected.some((source) => taintLabels.some((label) => label.source === source));
}

function matchesParameters(
	matchers: PolicyMatch["parameters"],
	params: Record<string, unknown>,
): boolean {
	if (matchers === undefined) return true;

	for (const [key, matcher] of Object.entries(matchers)) {
		const value = String(params[key] ?? "");

		if (matcher.pattern) {
			// Safety check: reject oversized attacker-controlled input before regex evaluation.
			// Oversized input could trigger catastrophic backtracking even in simple patterns.
			if (value.length > MAX_REGEX_INPUT_LENGTH) {
				throw new UnsafeMatchError(
					`Parameter '${key}' exceeds maximum safe length for regex evaluation (${value.length} > ${MAX_REGEX_INPUT_LENGTH}). Treating as unsafe — rule will be force-matched to ensure deny rules fire.`,
				);
			}

			try {
				const regex = new RegExp(matcher.pattern);
				if (!regex.test(value)) return false;
			} catch {
				// Invalid regex in policy definition — cannot evaluate safely.
				// Throw to ensure the policy engine denies the action rather than
				// silently skipping a potentially critical deny rule.
				throw new UnsafeMatchError(
					`Invalid regex pattern '${matcher.pattern}' in policy parameter matcher for '${key}'. Cannot evaluate — treating as unsafe.`,
				);
			}
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
