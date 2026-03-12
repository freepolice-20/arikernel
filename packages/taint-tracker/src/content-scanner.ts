/**
 * Content-based taint detection.
 *
 * Scans tool output data for prompt injection patterns and returns
 * taint labels derived from the content itself — not from manual annotation.
 * This ensures taint originates from actual malicious content rather than
 * relying on the agent to self-report taint.
 */

import type { TaintLabel, TaintSource } from "@arikernel/core";
import { createTaintLabel } from "./labels.js";

/** A detected injection signal with its source classification and confidence. */
export interface InjectionSignal {
	source: TaintSource;
	origin: string;
	confidence: number;
	pattern: string;
}

/**
 * Patterns that indicate prompt injection in tool output.
 * Each pattern maps to a taint source and confidence level.
 */
const INJECTION_PATTERNS: Array<{
	regex: RegExp;
	source: TaintSource;
	confidence: number;
	label: string;
}> = [
	// Direct instruction injection
	{
		regex: /ignore\s+(previous|all|prior|above)\s+(instructions?|prompts?|rules?)/i,
		source: "web",
		confidence: 0.95,
		label: "instruction-override",
	},
	{
		regex: /disregard\s+(previous|all|prior|your)\s+(instructions?|prompts?|guidelines?)/i,
		source: "web",
		confidence: 0.95,
		label: "instruction-override",
	},
	// Command injection via content
	{
		regex:
			/(?:read|cat|send|post|curl|wget|exfiltrate|steal)\s+.*(?:\.ssh|id_rsa|credentials|\.env|passwd|shadow|secret|token|api.?key)/i,
		source: "web",
		confidence: 0.9,
		label: "exfiltration-instruction",
	},
	// System prompt extraction
	{
		regex:
			/(?:print|output|reveal|show|display)\s+.*(?:system\s*prompt|instructions|initial\s*prompt)/i,
		source: "web",
		confidence: 0.85,
		label: "prompt-extraction",
	},
	// Role hijacking
	{
		regex: /you\s+are\s+(?:now|actually)\s+(?:a|an)\s+/i,
		source: "web",
		confidence: 0.8,
		label: "role-hijack",
	},
	// Data exfiltration setup
	{
		regex: /send\s+(?:it|the|this|all|data|contents?|results?)\s+to\s+https?:\/\//i,
		source: "web",
		confidence: 0.9,
		label: "exfiltration-instruction",
	},
	// Hidden instruction markers
	{
		regex: /\[SYSTEM\]|\[ADMIN\]|\[OVERRIDE\]|<\s*system\s*>|<\s*instruction\s*>/i,
		source: "web",
		confidence: 0.85,
		label: "fake-system-marker",
	},
	// Base64/encoded payload indicators
	{
		regex:
			/(?:execute|run|eval)\s+(?:the\s+)?(?:following|this)\s+(?:command|code|script|payload)/i,
		source: "web",
		confidence: 0.85,
		label: "code-execution-instruction",
	},
];

/**
 * Extract text content from a tool result's data field.
 * Handles strings, objects with body/content/text fields, and nested structures.
 */
function extractText(data: unknown): string {
	if (data === null || data === undefined) return "";
	if (typeof data === "string") return data;
	if (typeof data !== "object") return String(data);

	const parts: string[] = [];
	const obj = data as Record<string, unknown>;

	// Extract common response fields
	for (const key of ["body", "content", "text", "message", "data", "output", "result"]) {
		if (key in obj) {
			parts.push(extractText(obj[key]));
		}
	}

	// If no known fields matched, stringify the whole object
	if (parts.length === 0) {
		try {
			parts.push(JSON.stringify(data));
		} catch {
			/* circular or too large — skip */
		}
	}

	return parts.join("\n");
}

/**
 * Scan tool output data for prompt injection patterns.
 *
 * Returns taint labels derived from the content itself. The origin field
 * identifies which pattern matched, providing forensic traceability.
 */
export function scanForInjection(data: unknown, callId: string): TaintLabel[] {
	const text = extractText(data);
	if (!text || text.length < 10) return [];

	const signals: InjectionSignal[] = [];
	const seen = new Set<string>();

	for (const pattern of INJECTION_PATTERNS) {
		if (pattern.regex.test(text)) {
			const key = `${pattern.source}:${pattern.label}`;
			if (!seen.has(key)) {
				seen.add(key);
				signals.push({
					source: pattern.source,
					origin: `content-scan:${pattern.label}`,
					confidence: pattern.confidence,
					pattern: pattern.label,
				});
			}
		}
	}

	return signals.map((s) => createTaintLabel(s.source, s.origin, s.confidence, callId));
}
