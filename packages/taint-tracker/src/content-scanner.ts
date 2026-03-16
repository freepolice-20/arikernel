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
		source: "content-scan",
		confidence: 0.95,
		label: "instruction-override",
	},
	{
		regex: /disregard\s+(previous|all|prior|your)\s+(instructions?|prompts?|guidelines?)/i,
		source: "content-scan",
		confidence: 0.95,
		label: "instruction-override",
	},
	// Indirect instruction override (softer phrasing)
	{
		regex:
			/(?:forget|override|bypass|skip|drop)\s+(?:all\s+)?(?:(?:previous|prior|above|existing|your)\s+)*(?:instructions?|rules?|constraints?|guidelines?)/i,
		source: "content-scan",
		confidence: 0.9,
		label: "instruction-override",
	},
	// "New instructions" / "updated instructions" phrasing
	{
		regex: /(?:new|updated|revised|replacement)\s+(?:system\s+)?instructions?\s*:/i,
		source: "content-scan",
		confidence: 0.85,
		label: "instruction-override",
	},
	// Command injection via content
	{
		regex:
			/(?:read|cat|send|post|curl|wget|exfiltrate|steal)\s+.*(?:\.ssh|id_rsa|credentials|\.env|passwd|shadow|secret|token|api.?key)/i,
		source: "content-scan",
		confidence: 0.9,
		label: "exfiltration-instruction",
	},
	// Broader exfil phrasing: "access", "retrieve", "fetch", "get", "grab", "copy"
	{
		regex:
			/(?:access|retrieve|fetch|get|grab|copy|extract|download)\s+.*(?:\.ssh|id_rsa|credentials|\.env|passwd|shadow|secret|token|api.?key|private.?key)/i,
		source: "content-scan",
		confidence: 0.85,
		label: "exfiltration-instruction",
	},
	// System prompt extraction
	{
		regex:
			/(?:print|output|reveal|show|display)\s+.*(?:system\s*prompt|instructions|initial\s*prompt)/i,
		source: "content-scan",
		confidence: 0.85,
		label: "prompt-extraction",
	},
	// Broader prompt extraction: "what are your instructions", "repeat your prompt"
	{
		regex:
			/(?:what\s+are\s+your|repeat\s+your|tell\s+me\s+your|share\s+your)\s+(?:system\s+)?(?:instructions?|prompt|rules?|guidelines?)/i,
		source: "content-scan",
		confidence: 0.8,
		label: "prompt-extraction",
	},
	// Role hijacking
	{
		regex: /you\s+are\s+(?:now|actually)\s+(?:a|an)\s+/i,
		source: "content-scan",
		confidence: 0.8,
		label: "role-hijack",
	},
	// Data exfiltration setup
	{
		regex: /send\s+(?:it|the|this|all|data|contents?|results?)\s+to\s+https?:\/\//i,
		source: "content-scan",
		confidence: 0.9,
		label: "exfiltration-instruction",
	},
	// Broader exfil: "upload to", "forward to", "pipe to", "write to" + URL
	{
		regex: /(?:upload|forward|pipe|transmit|relay|write)\s+.*to\s+https?:\/\//i,
		source: "content-scan",
		confidence: 0.85,
		label: "exfiltration-instruction",
	},
	// Hidden instruction markers
	{
		regex: /\[SYSTEM\]|\[ADMIN\]|\[OVERRIDE\]|<\s*system\s*>|<\s*instruction\s*>/i,
		source: "content-scan",
		confidence: 0.85,
		label: "fake-system-marker",
	},
	// Invisible / zero-width character sequences (used to hide instructions)
	{
		regex: /(?:\u200B|\u200C|\u200D|\u2060|\uFEFF){3,}/,
		source: "content-scan",
		confidence: 0.8,
		label: "invisible-text",
	},
	// Base64/encoded payload indicators
	{
		regex:
			/(?:execute|run|eval)\s+(?:the\s+)?(?:following|this)\s+(?:command|code|script|payload)/i,
		source: "content-scan",
		confidence: 0.85,
		label: "code-execution-instruction",
	},
	// Multi-line delimiter injection (```system, ---SYSTEM---, ===INSTRUCTIONS===)
	{
		regex: /(?:```|---+|===+)\s*(?:system|admin|instruction|override|hidden)/i,
		source: "content-scan",
		confidence: 0.8,
		label: "delimiter-injection",
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
	const rawText = extractText(data);
	if (!rawText || rawText.length < 10) return [];
	// NFKC-normalize to defeat Unicode homoglyph bypass (e.g. Cyrillic і/е for ASCII i/e)
	const text = rawText.normalize("NFKC");

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
