/**
 * Reference DLP output filter for detecting secrets in tool results.
 *
 * Provides a ready-to-use `onOutputFilter` hook that scans string output
 * for common secret patterns and replaces them with [REDACTED].
 * Users can supply their own filter for production use.
 */

import type { ToolCall, ToolResult, TaintLabel } from '@arikernel/core';
import { now } from '@arikernel/core';

/** Pattern definition for secret detection. */
interface SecretPattern {
	name: string;
	regex: RegExp;
}

const DEFAULT_PATTERNS: SecretPattern[] = [
	{ name: 'aws-access-key', regex: /AKIA[0-9A-Z]{16}/g },
	{ name: 'private-key', regex: /-----BEGIN\s[\w\s]*PRIVATE KEY-----/g },
	{ name: 'github-token', regex: /gh[ps]_[A-Za-z0-9_]{36,}/g },
	{ name: 'bearer-token', regex: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/g },
	{ name: 'generic-api-key', regex: /(?:api[_-]?key|apikey)\s*[:=]\s*["']?[A-Za-z0-9\-._]{20,}["']?/gi },
	{ name: 'base64-blob', regex: /[A-Za-z0-9+/]{64,}={0,2}/g },
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
 * Create an `onOutputFilter` hook that scans tool result data for secrets.
 * String data is scanned and redacted. Non-string data passes through unchanged.
 */
export function createSecretPatternFilter(options?: OutputFilterOptions) {
	const patterns = options?.patterns ?? [...DEFAULT_PATTERNS, ...(options?.extraPatterns ?? [])];
	const replacement = options?.replacement ?? '[REDACTED]';

	return (_toolCall: ToolCall, result: ToolResult): ToolResult => {
		if (typeof result.data !== 'string') return result;

		let filtered = result.data;
		const detected: string[] = [];

		for (const pattern of patterns) {
			// Reset lastIndex for global regexes
			pattern.regex.lastIndex = 0;
			if (pattern.regex.test(filtered)) {
				detected.push(pattern.name);
				pattern.regex.lastIndex = 0;
				filtered = filtered.replace(pattern.regex, replacement);
			}
		}

		if (detected.length === 0) return result;

		const redactedLabel: TaintLabel = {
			source: 'tool-output',
			origin: `redacted:${detected.join(',')}`,
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
