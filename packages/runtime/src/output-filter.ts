/**
 * Reference DLP output filter for detecting secrets in tool results.
 *
 * Provides a ready-to-use `onOutputFilter` hook that scans string output
 * for common secret patterns and replaces them with [REDACTED].
 * Users can supply their own filter for production use.
 */

import type { TaintLabel, ToolCall, ToolResult } from "@arikernel/core";
import { now } from "@arikernel/core";

/** Pattern definition for secret detection. */
interface SecretPattern {
	name: string;
	regex: RegExp;
}

const DEFAULT_PATTERNS: SecretPattern[] = [
	{ name: "aws-access-key", regex: /AKIA[0-9A-Z]{16}/g },
	{ name: "private-key", regex: /-----BEGIN\s[\w\s]{0,40}PRIVATE KEY-----/g },
	{ name: "github-token", regex: /gh[ps]_[A-Za-z0-9_]{36,255}/g },
	{ name: "bearer-token", regex: /Bearer\s+[A-Za-z0-9\-._~+/]{1,500}=*/g },
	{
		name: "generic-api-key",
		regex: /(?:api[_-]?key|apikey)\s{0,5}[:=]\s{0,5}["']?[A-Za-z0-9\-._]{20,200}["']?/gi,
	},
	// Bounded length to prevent ReDoS on large alphanumeric blocks
	{ name: "base64-blob", regex: /[A-Za-z0-9+/]{64,1024}={0,2}/g },
];

export interface OutputFilterOptions {
	/** Additional patterns to scan for. Merged with defaults. */
	extraPatterns?: SecretPattern[];
	/** Replace defaults entirely with custom patterns. */
	patterns?: SecretPattern[];
	/** Replacement string. Default: '[REDACTED]' */
	replacement?: string;
}

/**
 * Recursively scan and redact secrets in structured data (objects, arrays, nested JSON).
 * Returns the redacted data and a set of detected pattern names.
 */
function scanAndRedact(
	data: unknown,
	patterns: SecretPattern[],
	replacement: string,
	detected: Set<string>,
	depth = 0,
): unknown {
	// Prevent infinite recursion on deeply nested structures
	if (depth > 20) return data;

	if (typeof data === "string") {
		let filtered = data;
		for (const pattern of patterns) {
			pattern.regex.lastIndex = 0;
			if (pattern.regex.test(filtered)) {
				detected.add(pattern.name);
				pattern.regex.lastIndex = 0;
				filtered = filtered.replace(pattern.regex, replacement);
			}
		}
		return filtered;
	}

	if (Array.isArray(data)) {
		return data.map((item) => scanAndRedact(item, patterns, replacement, detected, depth + 1));
	}

	if (data !== null && typeof data === "object") {
		const result: Record<string, unknown> = {};
		for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
			result[key] = scanAndRedact(value, patterns, replacement, detected, depth + 1);
		}
		return result;
	}

	return data;
}

/**
 * Create an `onOutputFilter` hook that scans tool result data for secrets.
 * Recursively traverses strings, objects, and arrays to redact secrets.
 */
export function createSecretPatternFilter(options?: OutputFilterOptions) {
	const patterns = options?.patterns ?? [...DEFAULT_PATTERNS, ...(options?.extraPatterns ?? [])];
	const replacement = options?.replacement ?? "[REDACTED]";

	return (_toolCall: ToolCall, result: ToolResult): ToolResult => {
		const detected = new Set<string>();
		const filtered = scanAndRedact(result.data, patterns, replacement, detected);

		if (detected.size === 0) return result;

		const redactedLabel: TaintLabel = {
			source: "tool-output",
			origin: `redacted:${Array.from(detected).join(",")}`,
			confidence: 1.0,
			addedAt: now(),
		};

		return {
			...result,
			data: filtered,
			taintLabels: [...result.taintLabels, redactedLabel],
		};
	};
}
