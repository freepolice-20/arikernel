/**
 * Simple static analysis to detect regex patterns at risk of catastrophic backtracking.
 *
 * Rejects patterns with nested quantifiers (e.g., (a+)+, (a*)*b, (a|b+)*)
 * which are the primary cause of ReDoS. This is a heuristic — it cannot catch
 * all vulnerable patterns, but it covers the most common attack vectors.
 *
 * Combined with the runtime MAX_REGEX_INPUT_LENGTH bound in matcher.ts,
 * this provides defense-in-depth against regex-based DoS.
 */

/** Characters that indicate a quantifier follows a group. */
const QUANTIFIERS = new Set(["*", "+", "?", "{"]);

/**
 * Check if a regex pattern has nested quantifiers (a quantifier applied to a
 * group that itself contains a quantifier). This is the classic ReDoS pattern.
 *
 * Returns an error message if unsafe, or null if the pattern appears safe.
 */
export function checkRegexSafety(pattern: string): string | null {
	try {
		new RegExp(pattern);
	} catch {
		// Invalid regex patterns are handled at runtime by UnsafeMatchError in matcher.ts.
		// Don't reject at load time — allow the fail-closed runtime behavior to apply.
		return null;
	}

	// Detect nested quantifiers by tracking group depth and quantifier presence
	let depth = 0;
	let quantifierInCurrentGroup = false;
	const groupHasQuantifier: boolean[] = [];
	let escaped = false;
	let inCharClass = false;

	for (let i = 0; i < pattern.length; i++) {
		const ch = pattern[i];

		if (escaped) {
			escaped = false;
			continue;
		}

		if (ch === "\\") {
			escaped = true;
			continue;
		}

		if (ch === "[") {
			inCharClass = true;
			continue;
		}
		if (ch === "]") {
			inCharClass = false;
			continue;
		}
		if (inCharClass) continue;

		if (ch === "(") {
			depth++;
			groupHasQuantifier.push(false);
			continue;
		}

		if (ch === ")") {
			if (depth > 0) {
				const innerHasQuantifier = groupHasQuantifier.pop() ?? false;
				depth--;

				// Check if the group itself is quantified
				const next = pattern[i + 1];
				if (next && QUANTIFIERS.has(next)) {
					if (innerHasQuantifier) {
						return `Regex pattern '${pattern}' contains nested quantifiers (potential ReDoS). A quantified group contains a quantifier — this can cause catastrophic backtracking.`;
					}
					// Mark parent group as having a quantifier
					if (groupHasQuantifier.length > 0) {
						groupHasQuantifier[groupHasQuantifier.length - 1] = true;
					}
				}
			}
			continue;
		}

		if (QUANTIFIERS.has(ch)) {
			if (groupHasQuantifier.length > 0) {
				groupHasQuantifier[groupHasQuantifier.length - 1] = true;
			}
			quantifierInCurrentGroup = true;
		}
	}

	return null;
}

/**
 * Validate all regex patterns in a set of policy rules.
 * Returns an array of error messages (empty if all patterns are safe).
 */
export function validatePolicyRegexSafety(
	rules: Array<{ id: string; match: { parameters?: Record<string, { pattern?: string }> } }>,
): string[] {
	const errors: string[] = [];

	for (const rule of rules) {
		if (!rule.match.parameters) continue;

		for (const [key, matcher] of Object.entries(rule.match.parameters)) {
			if (!matcher.pattern) continue;

			const error = checkRegexSafety(matcher.pattern);
			if (error) {
				errors.push(`Rule '${rule.id}', parameter '${key}': ${error}`);
			}
		}
	}

	return errors;
}
