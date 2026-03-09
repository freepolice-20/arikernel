/**
 * Replay Engine — re-evaluates a recorded trace through the kernel
 * to verify deterministic decision consistency.
 *
 * Replays security decisions only. External side effects (HTTP, file I/O)
 * are not re-executed — the engine stubs all executors.
 */

import type { PolicyRule, ToolCall, ToolResult } from "@arikernel/core";
import { DEFAULT_POLICIES, ToolCallDeniedError, getPreset, now } from "@arikernel/core";
import { Firewall } from "./firewall.js";
import type {
	ReplayMismatch,
	ReplayResult,
	ReplaySummary,
	ReplayTrace,
	ReplayedEvent,
	TraceDecision,
} from "./trace-types.js";

/** Options for configuring replay behavior. */
export interface ReplayEngineOptions {
	/**
	 * Override policy for what-if analysis.
	 * Accepts a YAML file path (string) or inline PolicyRule array.
	 * If provided, the replay uses these rules instead of the original.
	 */
	policies?: string | PolicyRule[];
	/**
	 * Override preset for what-if analysis.
	 * Ignored if `policies` is provided.
	 */
	preset?: string;
	/** Audit log path for the replay run (defaults to in-memory temp). */
	auditLog?: string;
}

/**
 * Replay a recorded trace through a fresh kernel instance.
 *
 * For each recorded event, the engine:
 * 1. Optionally requests the same capability
 * 2. Attempts to execute the same tool call
 * 3. Compares the kernel's decision with the recorded decision
 *
 * External executors are stubbed — no real side effects occur.
 */
export async function replayTrace(
	trace: ReplayTrace,
	options: ReplayEngineOptions = {},
): Promise<ReplayResult> {
	// Resolve policies: explicit override, or reconstruct from trace metadata
	const policies = resolvePolicies(trace, options);
	const auditLog = options.auditLog ?? ":memory:";

	// Create a fresh firewall with stubbed executors
	const firewall = new Firewall({
		principal: {
			name: trace.metadata.principal ?? "replay-agent",
			capabilities: buildReplayCapabilities(trace),
		},
		policies: policies as any,
		auditLog,
		runStatePolicy: {
			maxDeniedSensitiveActions: 5,
			behavioralRules: true,
		},
	});

	// Stub all executors — replay verifies security decisions, not real I/O
	for (const toolClass of ["http", "file", "shell", "database", "retrieval", "mcp"]) {
		firewall.registerExecutor({
			toolClass,
			async execute(toolCall: ToolCall): Promise<ToolResult> {
				return {
					callId: toolCall.id,
					success: true,
					data: null,
					durationMs: 0,
					taintLabels:
						toolCall.toolClass === "http"
							? [
									{
										source: "web" as const,
										origin: String(toolCall.parameters.url ?? ""),
										confidence: 1,
										addedAt: now(),
									},
								]
							: [],
				};
			},
		});
	}

	const replayedEvents: ReplayedEvent[] = [];
	const mismatches: ReplayMismatch[] = [];
	let replayAllowed = 0;
	let replayDenied = 0;

	try {
		for (const event of trace.events) {
			let replayedDecision: TraceDecision;

			// Request capability if the original event did
			if (event.capabilityClass) {
				const grant = firewall.requestCapability(event.capabilityClass as any);
				if (!grant.granted) {
					replayedDecision = {
						verdict: "deny",
						reason: grant.reason ?? "Capability denied",
						taintLabels: (grant.taintLabels ?? []).map((t) => ({
							source: t.source,
							origin: t.origin,
						})),
					};
					replayDenied++;
					const replayed: ReplayedEvent = {
						sequence: event.sequence,
						request: event.request,
						originalDecision: event.decision,
						replayedDecision,
						matched: event.decision.verdict === "deny",
					};
					replayedEvents.push(replayed);
					collectMismatches(event.sequence, event.decision, replayedDecision, mismatches);
					continue;
				}

				// Execute with grant
				try {
					await firewall.execute({
						...event.request,
						grantId: grant.grant!.id,
					});
					replayedDecision = {
						verdict: "allow",
						reason: "Allowed by policy",
						taintLabels: [],
					};
					replayAllowed++;
				} catch (err) {
					replayedDecision = decisionFromError(err);
					replayDenied++;
				}
			} else {
				// Execute without capability
				try {
					await firewall.execute(event.request);
					replayedDecision = {
						verdict: "allow",
						reason: "Allowed by policy",
						taintLabels: [],
					};
					replayAllowed++;
				} catch (err) {
					replayedDecision = decisionFromError(err);
					replayDenied++;
				}
			}

			const matched = event.decision.verdict === replayedDecision.verdict;
			const replayed: ReplayedEvent = {
				sequence: event.sequence,
				request: event.request,
				originalDecision: event.decision,
				replayedDecision,
				matched,
			};
			replayedEvents.push(replayed);
			collectMismatches(event.sequence, event.decision, replayedDecision, mismatches);
		}

		const replayQuarantined = firewall.isRestricted;
		const summary: ReplaySummary = {
			totalEvents: trace.events.length,
			matched: replayedEvents.filter((e) => e.matched).length,
			mismatched: mismatches.length > 0 ? replayedEvents.filter((e) => !e.matched).length : 0,
			originalQuarantined: trace.outcome.quarantined,
			replayQuarantined,
			allowed: replayAllowed,
			denied: replayDenied,
		};

		return {
			trace,
			replayedEvents,
			allMatched: mismatches.length === 0,
			mismatches,
			quarantineMatched: trace.outcome.quarantined === replayQuarantined,
			summary,
		};
	} finally {
		firewall.close();
	}
}

function decisionFromError(err: unknown): TraceDecision {
	if (err instanceof ToolCallDeniedError) {
		return {
			verdict: "deny",
			reason: err.decision.reason,
			matchedRule: err.decision.matchedRule?.id,
			taintLabels: err.decision.taintLabels.map((t) => ({
				source: t.source,
				origin: t.origin,
			})),
		};
	}
	return {
		verdict: "deny",
		reason: err instanceof Error ? err.message : String(err),
		taintLabels: [],
	};
}

function collectMismatches(
	sequence: number,
	original: TraceDecision,
	replayed: TraceDecision,
	mismatches: ReplayMismatch[],
): void {
	if (original.verdict !== replayed.verdict) {
		mismatches.push({
			sequence,
			field: "verdict",
			original: original.verdict,
			replayed: replayed.verdict,
		});
	}
}

/**
 * Resolve policies for replay. Uses override if provided,
 * otherwise falls back to safe defaults that match the original run's preset.
 */
function resolvePolicies(trace: ReplayTrace, options: ReplayEngineOptions): string | PolicyRule[] {
	if (options.policies) {
		return options.policies;
	}

	// If a preset was specified, use it
	if (options.preset || trace.metadata.preset) {
		const presetId = options.preset ?? trace.metadata.preset;
		try {
			const preset = getPreset(presetId as any);
			return preset.policies;
		} catch {
			// Fall through to safe defaults
		}
	}

	// Use safe defaults — same as the DEFAULT_POLICIES from core
	return DEFAULT_POLICIES;
}

/**
 * Build capability set from trace events.
 * Extracts all tool classes and actions seen in the trace to give the
 * replay agent the same base capabilities.
 */
function buildReplayCapabilities(trace: ReplayTrace) {
	const capMap = new Map<string, Set<string>>();
	const hostSet = new Set<string>();
	const pathSet = new Set<string>();

	for (const event of trace.events) {
		const tc = event.request.toolClass;
		if (!capMap.has(tc)) {
			capMap.set(tc, new Set());
		}
		capMap.get(tc)!.add(event.request.action);

		// Only extract constraints from ALLOWED events to preserve original enforcement
		if (event.decision.verdict !== "allow") continue;

		const params = event.request.parameters;
		if (tc === "http" && params.url) {
			try {
				const url = new URL(params.url as string);
				hostSet.add(url.hostname);
			} catch {}
		}
		if (tc === "file" && params.path) {
			pathSet.add(params.path as string);
		}
	}

	return Array.from(capMap.entries()).map(([toolClass, actions]) => ({
		toolClass: toolClass as any,
		actions: Array.from(actions),
		constraints:
			toolClass === "http"
				? { allowedHosts: hostSet.size > 0 ? Array.from(hostSet) : [] }
				: toolClass === "file"
					? { allowedPaths: pathSet.size > 0 ? Array.from(pathSet) : [] }
					: {},
	}));
}
