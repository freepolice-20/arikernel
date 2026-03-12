/**
 * Behavioral sequence rules for run-state enforcement.
 *
 * Six explicit rules that detect suspicious multi-step patterns
 * in the recent-event window and trigger immediate quarantine.
 * No DSL, no graph engine — just direct pattern matching.
 */

import type { QuarantineInfo, RunStateTracker, SecurityEvent } from "./run-state.js";

export interface BehavioralRuleMatch {
	ruleId: string;
	reason: string;
	matchedEvents: SecurityEvent[];
}

/**
 * Risk ordering for tool classes. Higher number = more dangerous.
 * Used by rule 2 to detect capability escalation.
 */
const TOOL_CLASS_RISK: Record<string, number> = {
	http: 1, // read-only HTTP is low risk
	database: 2, // data access
	file: 3, // filesystem access
	shell: 5, // arbitrary code execution
};

const DANGEROUS_CLASSES = new Set(["shell", "file"]);

/**
 * Evaluate all behavioral sequence rules against the recent-event window.
 * Returns the first matching rule, or null if none match.
 */
export function evaluateBehavioralRules(state: RunStateTracker): BehavioralRuleMatch | null {
	if (state.restricted) return null;

	const events = state.recentEvents;
	if (events.length < 2) return null;

	return (
		checkWebTaintSensitiveProbe(events, state) ??
		checkDeniedCapabilityThenEscalation(events, state) ??
		checkSensitiveReadThenEgress(events, state) ??
		checkTaintedDatabaseWrite(events, state) ??
		checkTaintedShellWithData(events, state) ??
		checkSecretAccessThenAnyEgress(events, state)
	);
}

/**
 * Apply a behavioral rule match to quarantine the run.
 * Returns QuarantineInfo if newly quarantined, null if already restricted.
 */
export function applyBehavioralRule(
	state: RunStateTracker,
	match: BehavioralRuleMatch,
): QuarantineInfo | null {
	return state.quarantineByRule(match.ruleId, match.reason, match.matchedEvents);
}

// ── Rule 1: web_taint_sensitive_probe ──────────────────────────────
//
// If untrusted web taint was recently observed, and shortly after the run
// attempts sensitive file reads, shell exec, or outbound egress → quarantine.

function checkWebTaintSensitiveProbe(
	events: readonly SecurityEvent[],
	state: RunStateTracker,
): BehavioralRuleMatch | null {
	// Check window for taint event, OR consult sticky flag
	const taintEvent = findRecent(
		events,
		(e) =>
			e.type === "taint_observed" &&
			e.taintSources?.some((s) => s === "web" || s === "rag" || s === "email") === true,
	);
	const hasTaintSticky =
		state.tainted &&
		[...state.taintSources].some((s) => s === "web" || s === "rag" || s === "email");
	if (!taintEvent && !hasTaintSticky) return null;

	// If taint event is in window, look for dangerous follow-up after it
	// If taint was evicted from window but sticky flag is set, any dangerous event in window triggers
	const searchFromIdx = taintEvent ? events.indexOf(taintEvent) : -1;

	const dangerousFollowup = findAfter(
		events,
		searchFromIdx,
		(e) =>
			e.type === "sensitive_read_attempt" ||
			(e.type === "tool_call_denied" && e.toolClass === "shell") ||
			(e.type === "tool_call_allowed" && e.toolClass === "shell") ||
			e.type === "egress_attempt",
	);

	if (!dangerousFollowup) return null;

	const actionDesc = dangerousFollowup.toolClass
		? `${dangerousFollowup.toolClass}.${dangerousFollowup.action ?? "*"}`
		: dangerousFollowup.type;

	return {
		ruleId: "web_taint_sensitive_probe",
		reason: `Untrusted web input was followed by ${actionDesc} attempt`,
		matchedEvents: taintEvent ? [taintEvent, dangerousFollowup] : [dangerousFollowup],
	};
}

// ── Rule 2: denied_capability_then_escalation ──────────────────────
//
// If a capability request is denied, and shortly after the run requests
// a broader or riskier capability → quarantine.

function checkDeniedCapabilityThenEscalation(
	events: readonly SecurityEvent[],
	state: RunStateTracker,
): BehavioralRuleMatch | null {
	// Check ALL denied capabilities in the window to find
	// any denial followed by a riskier request.
	for (let i = 0; i < events.length; i++) {
		const event = events[i];
		if (event.type !== "capability_denied") continue;

		// Set sticky flag whenever we see a denial (survives window eviction)
		state.markEscalationDenied(event.toolClass ?? "");

		const deniedRisk = TOOL_CLASS_RISK[event.toolClass ?? ""] ?? 0;

		const escalation = findAfter(events, i, (e) => {
			if (e.type !== "capability_requested" && e.type !== "capability_granted") return false;
			const requestedRisk = TOOL_CLASS_RISK[e.toolClass ?? ""] ?? 0;

			// Escalation: requesting something riskier, or requesting a dangerous class
			if (requestedRisk > deniedRisk) return true;
			if (DANGEROUS_CLASSES.has(e.toolClass ?? "")) return true;

			return false;
		});

		if (escalation) {
			return {
				ruleId: "denied_capability_then_escalation",
				reason: `Denied ${event.toolClass ?? "unknown"} capability was followed by escalation to ${escalation.toolClass ?? "unknown"}`,
				matchedEvents: [event, escalation],
			};
		}
	}

	// Sticky flag: capability denial happened earlier but was evicted from window.
	// Only activates when NO capability_denied events remain in the window
	// (otherwise the for-loop above already handles them with proper ordering).
	const hasDenialInWindow = events.some((e) => e.type === "capability_denied");
	if (state.escalationDeniedObserved && !hasDenialInWindow) {
		const deniedRisk = TOOL_CLASS_RISK[state.escalationDeniedToolClass ?? ""] ?? 0;
		const escalation = findRecent(events, (e) => {
			if (e.type !== "capability_requested" && e.type !== "capability_granted") return false;
			const requestedRisk = TOOL_CLASS_RISK[e.toolClass ?? ""] ?? 0;
			if (requestedRisk > deniedRisk) return true;
			if (DANGEROUS_CLASSES.has(e.toolClass ?? "")) return true;
			return false;
		});

		if (escalation) {
			return {
				ruleId: "denied_capability_then_escalation",
				reason: `Previous denied ${state.escalationDeniedToolClass ?? "unknown"} capability was followed by escalation to ${escalation.toolClass ?? "unknown"}`,
				matchedEvents: [escalation],
			};
		}
	}

	return null;
}

// ── Rule 3: sensitive_read_then_egress ─────────────────────────────
//
// If the run reads (or attempts to read) sensitive local data, and
// shortly after attempts outbound POST/write/upload → quarantine.

function checkSensitiveReadThenEgress(
	events: readonly SecurityEvent[],
	state: RunStateTracker,
): BehavioralRuleMatch | null {
	const sensitiveRead = findRecent(
		events,
		(e) => e.type === "sensitive_read_attempt" || e.type === "sensitive_read_allowed",
	);

	// If sensitive read is in window, look for egress after it
	// If sensitive read was evicted but sticky flag is set, any egress in window triggers
	if (sensitiveRead) {
		const readIdx = events.indexOf(sensitiveRead);
		const egress = findAfter(events, readIdx, (e) => e.type === "egress_attempt");
		if (!egress) return null;

		const path = (sensitiveRead.metadata?.path as string) ?? "sensitive file";
		return {
			ruleId: "sensitive_read_then_egress",
			reason: `Read of ${path} was followed by outbound ${egress.action ?? "write"} attempt`,
			matchedEvents: [sensitiveRead, egress],
		};
	}

	// Sticky flag: sensitive read happened earlier but was evicted from window
	if (state.sensitiveReadObserved) {
		const egress = findRecent(events, (e) => e.type === "egress_attempt");
		if (!egress) return null;

		return {
			ruleId: "sensitive_read_then_egress",
			reason: `Previous sensitive file read was followed by outbound ${egress.action ?? "write"} attempt`,
			matchedEvents: [egress],
		};
	}

	return null;
}

// ── Rule 4: tainted_database_write ─────────────────────────────────
//
// If untrusted taint was observed, and the run then attempts a database
// write/exec/mutate action → quarantine. Prevents tainted SQL injection.

const DB_WRITE_ACTIONS = new Set(["exec", "write", "insert", "update", "delete", "mutate"]);

function checkTaintedDatabaseWrite(
	events: readonly SecurityEvent[],
	state: RunStateTracker,
): BehavioralRuleMatch | null {
	const taintEvent = findRecent(
		events,
		(e) =>
			e.type === "taint_observed" &&
			e.taintSources?.some((s) => s === "web" || s === "rag" || s === "email") === true,
	);
	const hasTaintSticky =
		state.tainted &&
		[...state.taintSources].some((s) => s === "web" || s === "rag" || s === "email");
	if (!taintEvent && !hasTaintSticky) return null;

	const searchFromIdx = taintEvent ? events.indexOf(taintEvent) : -1;

	const dbWrite = findAfter(
		events,
		searchFromIdx,
		(e) => e.toolClass === "database" && DB_WRITE_ACTIONS.has(e.action ?? ""),
	);
	if (!dbWrite) return null;

	return {
		ruleId: "tainted_database_write",
		reason: `Untrusted input was followed by database ${dbWrite.action} attempt`,
		matchedEvents: taintEvent ? [taintEvent, dbWrite] : [dbWrite],
	};
}

// ── Rule 5: tainted_shell_with_data ────────────────────────────────
//
// If untrusted taint was observed, and the run then executes a shell
// command with a long command string (suggesting data is being piped
// or exfiltrated via command args) → quarantine.

const SHELL_DATA_CMD_LENGTH = 100;

function checkTaintedShellWithData(
	events: readonly SecurityEvent[],
	state: RunStateTracker,
): BehavioralRuleMatch | null {
	const taintEvent = findRecent(
		events,
		(e) =>
			e.type === "taint_observed" &&
			e.taintSources?.some((s) => s === "web" || s === "rag" || s === "email") === true,
	);
	const hasTaintSticky =
		state.tainted &&
		[...state.taintSources].some((s) => s === "web" || s === "rag" || s === "email");
	if (!taintEvent && !hasTaintSticky) return null;

	const searchFromIdx = taintEvent ? events.indexOf(taintEvent) : -1;

	const shellWithData = findAfter(events, searchFromIdx, (e) => {
		if (e.toolClass !== "shell") return false;
		const cmdLen = (e.metadata?.commandLength as number) ?? 0;
		return cmdLen > SHELL_DATA_CMD_LENGTH;
	});
	if (!shellWithData) return null;

	return {
		ruleId: "tainted_shell_with_data",
		reason: `Untrusted input was followed by shell exec with long command (${(shellWithData.metadata?.commandLength as number) ?? "?"} chars)`,
		matchedEvents: taintEvent ? [taintEvent, shellWithData] : [shellWithData],
	};
}

// ── Rule 6: secret_access_then_any_egress ──────────────────────────
//
// If the run accessed credentials/vault-like resources (via database
// query to secrets tables or HTTP to vault endpoints), and then
// attempts any egress → quarantine.

const SECRETS_DB_PATTERNS = /secret|credential|password|token|vault|key_store/i;
const SECRETS_URL_PATTERNS = /vault|secrets|credentials|\.well-known\/keys/i;

function checkSecretAccessThenAnyEgress(
	events: readonly SecurityEvent[],
	state: RunStateTracker,
): BehavioralRuleMatch | null {
	// Look for database queries or HTTP GETs that touched secrets-like resources
	const secretAccess = findRecent(events, (e) => {
		if (e.toolClass === "database" && e.action === "query") {
			const query = (e.metadata?.query as string) ?? "";
			return SECRETS_DB_PATTERNS.test(query);
		}
		if (e.toolClass === "http" && (e.action === "get" || e.action === "head")) {
			const url = (e.metadata?.url as string) ?? "";
			return SECRETS_URL_PATTERNS.test(url);
		}
		return false;
	});

	// Set sticky flag whenever we detect secret access, even if no egress follows yet
	if (secretAccess) {
		state.markSecretAccess();
		const accessIdx = events.indexOf(secretAccess);
		const egress = findAfter(events, accessIdx, (e) => e.type === "egress_attempt");
		if (!egress) return null;

		const resource =
			secretAccess.toolClass === "database"
				? "database query"
				: `HTTP ${secretAccess.action} to ${(secretAccess.metadata?.url as string) ?? "unknown"}`;

		return {
			ruleId: "secret_access_then_any_egress",
			reason: `${resource} accessing secrets was followed by ${egress.action ?? "egress"} attempt`,
			matchedEvents: [secretAccess, egress],
		};
	}

	// Sticky flag: secret access happened earlier but was evicted from window
	if (state.secretAccessObserved) {
		const egress = findRecent(events, (e) => e.type === "egress_attempt");
		if (!egress) return null;

		return {
			ruleId: "secret_access_then_any_egress",
			reason: `Previous secret access was followed by ${egress.action ?? "egress"} attempt`,
			matchedEvents: [egress],
		};
	}

	return null;
}

// ── Helpers ────────────────────────────────────────────────────────

function findRecent(
	events: readonly SecurityEvent[],
	predicate: (e: SecurityEvent) => boolean,
): SecurityEvent | null {
	// Search backwards to find the most recent match
	for (let i = events.length - 1; i >= 0; i--) {
		if (predicate(events[i])) return events[i];
	}
	return null;
}

function findAfter(
	events: readonly SecurityEvent[],
	afterIndex: number,
	predicate: (e: SecurityEvent) => boolean,
): SecurityEvent | null {
	for (let i = afterIndex + 1; i < events.length; i++) {
		if (predicate(events[i])) return events[i];
	}
	return null;
}
