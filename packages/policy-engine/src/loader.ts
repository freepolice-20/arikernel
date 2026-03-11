import { readFileSync } from "node:fs";
import { type PolicyRule, PolicyValidationError, policySetSchema } from "@arikernel/core";
import { parse as parseYaml } from "yaml";
import { validatePolicyRegexSafety } from "./safe-regex.js";

export function loadPolicyFile(filePath: string): PolicyRule[] {
	const content = readFileSync(filePath, "utf-8");
	const raw = parseYaml(content);
	const result = policySetSchema.safeParse(raw);

	if (!result.success) {
		throw new PolicyValidationError(`Invalid policy file: ${filePath}`, result.error.errors);
	}

	// SECURITY: Reject policy rules with regex patterns that risk catastrophic backtracking.
	// This is checked at load time to prevent ReDoS at runtime.
	const regexErrors = validatePolicyRegexSafety(result.data.rules);
	if (regexErrors.length > 0) {
		throw new PolicyValidationError(
			`Policy file '${filePath}' contains unsafe regex patterns`,
			regexErrors.map((msg) => ({ message: msg, path: [], code: "custom" })),
		);
	}

	return result.data.rules;
}

export function loadPolicies(source: string | PolicyRule[]): PolicyRule[] {
	if (Array.isArray(source)) {
		const regexErrors = validatePolicyRegexSafety(source);
		if (regexErrors.length > 0) {
			throw new PolicyValidationError(
				"Inline policy rules contain unsafe regex patterns",
				regexErrors.map((msg) => ({ message: msg, path: [], code: "custom" })),
			);
		}
		return source;
	}
	return loadPolicyFile(source);
}
