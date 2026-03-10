/**
 * Run-level state tracker for stateful enforcement.
 *
 * Tracks cumulative behavior counters and a recent-event window
 * across an entire agent run. When thresholds are exceeded or
 * behavioral sequence rules match, the run enters "restricted mode"
 * which limits the agent to read-only safe actions.
 */

import type { TaintLabel, TaintState } from "@arikernel/core";
import { normalizeInput } from "./unicode-safety.js";

export interface RunStatePolicy {
	/** Number of denied sensitive actions before entering restricted mode. Default: 5 */
	maxDeniedSensitiveActions?: number;
	/** Whether behavioral sequence rules are enabled. Default: true */
	behavioralRules?: boolean;
}

export interface RunStateCounters {
	deniedActions: number;
	capabilityRequests: number;
	deniedCapabilityRequests: number;
	externalEgressAttempts: number;
	sensitiveFileReadAttempts: number;
}

// ── Recent-event window types ──────────────────────────────────────

export type SecurityEventType =
	| "capability_requested"
	| "capability_denied"
	| "capability_granted"
	| "tool_call_allowed"
	| "tool_call_denied"
	| "taint_observed"
	| "sensitive_read_attempt"
	| "sensitive_read_allowed"
	| "egress_attempt"
	| "quarantine_entered";

export interface SecurityEvent {
	timestamp: string;
	type: SecurityEventType;
	toolClass?: string;
	action?: string;
	verdict?: "allow" | "deny" | "require-approval";
	taintSources?: string[];
	metadata?: Record<string, unknown>;
}

// ── Quarantine metadata ────────────────────────────────────────────

export type QuarantineTrigger = "threshold" | "behavioral_rule";

export interface QuarantineInfo {
	triggerType: QuarantineTrigger;
	ruleId?: string;
	reason: string;
	countersSnapshot: RunStateCounters;
	matchedEvents?: SecurityEvent[];
	timestamp: string;
}

// ── Constants ──────────────────────────────────────────────────────

const MAX_EVENT_WINDOW = 20;

/**
 * Actions considered "safe read-only" that are still allowed in restricted mode.
 *
 * HTTP GET/HEAD are allowed for content ingress (fetching pages to read).
 * Suspicious GET exfil patterns (large query strings, data-bearing params)
 * are caught separately by isSuspiciousGetExfil() in the pipeline.
 *
 * True egress methods (POST/PUT/PATCH/DELETE) are always blocked in quarantine.
 */
const SAFE_READONLY_ACTIONS: ReadonlyMap<string, ReadonlySet<string>> = new Map([
	["http", new Set(["get", "head", "options"])],
	["file", new Set(["read"])],
	["database", new Set(["query"])],
]);

/** Sensitive file path patterns that count toward sensitiveFileReadAttempts. */
const SENSITIVE_PATH_PATTERNS = [
	/\.ssh/i,
	/\.env/i,
	/\.aws/i,
	/credentials/i,
	/password/i,
	/secret/i,
	/\.gnupg/i,
	/id_rsa/i,
	/\.kube\/config/i,
	/token/i,
];

export class RunStateTracker {
	readonly counters: RunStateCounters = {
		deniedActions: 0,
		capabilityRequests: 0,
		deniedCapabilityRequests: 0,
		externalEgressAttempts: 0,
		sensitiveFileReadAttempts: 0,
	};

	private readonly _eventWindow: SecurityEvent[] = [];
	private _restricted = false;
	private _restrictedAt: string | null = null;
	private _quarantineInfo: QuarantineInfo | null = null;
	private _tainted = false;
	private _taintSources: Set<string> = new Set();
	private _accumulatedTaintLabels: TaintLabel[] = [];

	// ── Sticky state flags (H1 hardening) ──────────────────────────
	// These persist for the entire run and survive event window eviction.
	// Behavioral rules consult these so that an attacker cannot evade
	// detection by spacing steps across >20 events.
	private _sensitiveReadObserved = false;
	private _egressObserved = false;
	private _secretAccessObserved = false;
	private _quarantineGetCount = 0;
	private readonly threshold: number;
	readonly behavioralRulesEnabled: boolean;
	/** The policy configuration used to construct this tracker. */
	readonly policy: RunStatePolicy | undefined;

	constructor(policy?: RunStatePolicy) {
		this.policy = policy;
		this.threshold = policy?.maxDeniedSensitiveActions ?? 5;
		this.behavioralRulesEnabled = policy?.behavioralRules !== false;
	}

	get restricted(): boolean {
		return this._restricted;
	}

	get restrictedAt(): string | null {
		return this._restrictedAt;
	}

	get quarantineInfo(): QuarantineInfo | null {
		return this._quarantineInfo;
	}

	/**
	 * Whether the run has been tainted by untrusted external input.
	 * Once set, this flag never resets — it persists for the entire run.
	 */
	get tainted(): boolean {
		return this._tainted;
	}

	/** Set of taint source types observed during this run. */
	get taintSources(): ReadonlySet<string> {
		return this._taintSources;
	}

	/** Whether a sensitive file read was observed at any point during this run. Sticky. */
	get sensitiveReadObserved(): boolean {
		return this._sensitiveReadObserved;
	}

	/** Whether an egress attempt was observed at any point during this run. Sticky. */
	get egressObserved(): boolean {
		return this._egressObserved;
	}

	/** Whether a secret/credential access was observed at any point during this run. Sticky. */
	get secretAccessObserved(): boolean {
		return this._secretAccessObserved;
	}

	/** Mark the run as tainted by an external source. Sticky — never resets. */
	markTainted(source: string): void {
		this._tainted = true;
		this._taintSources.add(source);
	}

	/**
	 * Accumulate taint labels into the run-level taint state.
	 *
	 * Deduplicates by source:origin key so repeated labels don't bloat the set.
	 * This is the kernel's independent taint record — it persists even if tools
	 * or agents omit taint metadata from subsequent calls.
	 */
	accumulateTaintLabels(labels: TaintLabel[]): void {
		for (const label of labels) {
			const key = `${label.source}:${label.origin}`;
			if (!this._accumulatedTaintLabels.some((l) => `${l.source}:${l.origin}` === key)) {
				this._accumulatedTaintLabels.push(label);
			}
			this.markTainted(label.source);
		}
	}

	/** Read-only view of accumulated taint labels for the run. */
	get accumulatedTaintLabels(): readonly TaintLabel[] {
		return this._accumulatedTaintLabels;
	}

	/** Snapshot the kernel-maintained taint state for this run. */
	get taintState(): TaintState {
		return {
			tainted: this._tainted,
			sources: [...this._taintSources],
			labels: [...this._accumulatedTaintLabels],
		};
	}

	/** Read-only view of recent events. */
	get recentEvents(): readonly SecurityEvent[] {
		return this._eventWindow;
	}

	/**
	 * Maximum HTTP GETs with query parameters allowed after quarantine.
	 * Prevents slow-drip exfiltration via small GET requests that individually
	 * pass isSuspiciousGetExfil() thresholds.
	 */
	static readonly MAX_QUARANTINE_GETS_WITH_PARAMS = 3;

	/** Count of HTTP GETs with query params since quarantine. */
	get quarantineGetCount(): number {
		return this._quarantineGetCount;
	}

	/** Record a GET-with-params in quarantine mode. Returns true if budget exhausted. */
	recordQuarantineGet(): boolean {
		this._quarantineGetCount++;
		return this._quarantineGetCount > RunStateTracker.MAX_QUARANTINE_GETS_WITH_PARAMS;
	}

	/** Check if an action is allowed in restricted mode. */
	isAllowedInRestrictedMode(toolClass: string, action: string): boolean {
		return SAFE_READONLY_ACTIONS.get(toolClass)?.has(action) ?? false;
	}

	/** Push a security event into the recent window. */
	pushEvent(event: SecurityEvent): void {
		this._eventWindow.push(event);
		if (this._eventWindow.length > MAX_EVENT_WINDOW) {
			this._eventWindow.shift();
		}
	}

	/** Enter quarantine via behavioral rule. Returns QuarantineInfo if newly quarantined. */
	quarantineByRule(
		ruleId: string,
		reason: string,
		matchedEvents: SecurityEvent[],
	): QuarantineInfo | null {
		if (this._restricted) return null;
		const info: QuarantineInfo = {
			triggerType: "behavioral_rule",
			ruleId,
			reason,
			countersSnapshot: { ...this.counters },
			matchedEvents,
			timestamp: new Date().toISOString(),
		};
		this._restricted = true;
		this._restrictedAt = info.timestamp;
		this._quarantineInfo = info;
		this.pushEvent({
			timestamp: info.timestamp,
			type: "quarantine_entered",
			metadata: { ruleId, reason },
		});
		return info;
	}

	/** Record a denied action and check if we should enter restricted mode. */
	recordDeniedAction(): void {
		this.counters.deniedActions++;
		this.checkThreshold();
	}

	/** Record a capability request. */
	recordCapabilityRequest(granted: boolean): void {
		this.counters.capabilityRequests++;
		if (!granted) {
			this.counters.deniedCapabilityRequests++;
		}
	}

	/** Record an external egress attempt (HTTP write to any host). */
	recordEgressAttempt(): void {
		this.counters.externalEgressAttempts++;
		this._egressObserved = true;
	}

	/** Record a sensitive file read attempt. */
	recordSensitiveFileAttempt(): void {
		this.counters.sensitiveFileReadAttempts++;
		this._sensitiveReadObserved = true;
	}

	/** Mark that a secret/credential resource was accessed. Sticky. */
	markSecretAccess(): void {
		this._secretAccessObserved = true;
	}

	/** Check if a file path targets a sensitive location. NFKC-normalized to prevent homoglyph bypass. */
	isSensitivePath(path: string): boolean {
		const normalized = normalizeInput(path);
		return SENSITIVE_PATH_PATTERNS.some((p) => p.test(normalized));
	}

	/**
	 * Check if an HTTP action is a true egress (outbound write) attempt.
	 * Only write methods are egress. GET/HEAD are ingress (content fetch).
	 * Suspicious GET-based exfil is detected separately by isSuspiciousGetExfil().
	 */
	isEgressAction(action: string): boolean {
		return ["post", "put", "patch", "delete"].includes(action);
	}

	private checkThreshold(): void {
		if (this._restricted) return;
		if (this.counters.deniedActions >= this.threshold) {
			const ts = new Date().toISOString();
			this._restricted = true;
			this._restrictedAt = ts;
			this._quarantineInfo = {
				triggerType: "threshold",
				reason: `Denied actions (${this.counters.deniedActions}) exceeded threshold (${this.threshold})`,
				countersSnapshot: { ...this.counters },
				timestamp: ts,
			};
			this.pushEvent({
				timestamp: ts,
				type: "quarantine_entered",
				metadata: { triggerType: "threshold" },
			});
		}
	}
}

// ── Suspicious GET exfil detection ────────────────────────────────

/** Maximum query string length before a GET is flagged as suspicious exfil. */
const MAX_SAFE_QUERY_LENGTH = 256;

/** Maximum single query parameter value length. */
const MAX_SAFE_PARAM_VALUE_LENGTH = 128;

/**
 * Detect GET/HEAD requests that appear to be exfiltrating data via query parameters.
 *
 * Heuristic checks:
 * - Query string longer than 256 chars (data smuggling)
 * - Any single query parameter value longer than 128 chars (encoded payload)
 *
 * This is intentionally simple — it catches obvious exfil patterns without
 * becoming a full DLP engine. Normal page-fetch URLs pass through cleanly.
 */
export function isSuspiciousGetExfil(url: string): boolean {
	try {
		const parsed = new URL(url);
		const query = parsed.search;

		// No query string → definitely not exfil via query params
		if (!query || query.length <= 1) return false;

		// Long query strings suggest data smuggling
		if (query.length > MAX_SAFE_QUERY_LENGTH) return true;

		// Check individual parameter values for large payloads
		for (const [, value] of parsed.searchParams) {
			if (value.length > MAX_SAFE_PARAM_VALUE_LENGTH) return true;
		}

		return false;
	} catch {
		return false;
	}
}
