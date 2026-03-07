/**
 * Run-level state tracker for stateful enforcement.
 *
 * Tracks cumulative behavior counters and a recent-event window
 * across an entire agent run. When thresholds are exceeded or
 * behavioral sequence rules match, the run enters "restricted mode"
 * which limits the agent to read-only safe actions.
 */

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
	| 'capability_requested'
	| 'capability_denied'
	| 'capability_granted'
	| 'tool_call_allowed'
	| 'tool_call_denied'
	| 'taint_observed'
	| 'sensitive_read_attempt'
	| 'sensitive_read_allowed'
	| 'egress_attempt'
	| 'quarantine_entered';

export interface SecurityEvent {
	timestamp: string;
	type: SecurityEventType;
	toolClass?: string;
	action?: string;
	verdict?: 'allow' | 'deny' | 'require-approval';
	taintSources?: string[];
	metadata?: Record<string, unknown>;
}

// ── Quarantine metadata ────────────────────────────────────────────

export type QuarantineTrigger = 'threshold' | 'behavioral_rule';

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

/** Actions considered "safe read-only" that are still allowed in restricted mode. */
const SAFE_READONLY_ACTIONS: ReadonlyMap<string, ReadonlySet<string>> = new Map([
	['http', new Set(['get', 'head', 'options'])],
	['file', new Set(['read'])],
	['database', new Set(['query'])],
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
	private readonly threshold: number;
	readonly behavioralRulesEnabled: boolean;

	constructor(policy?: RunStatePolicy) {
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

	/** Read-only view of recent events. */
	get recentEvents(): readonly SecurityEvent[] {
		return this._eventWindow;
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
	quarantineByRule(ruleId: string, reason: string, matchedEvents: SecurityEvent[]): QuarantineInfo | null {
		if (this._restricted) return null;
		const info: QuarantineInfo = {
			triggerType: 'behavioral_rule',
			ruleId,
			reason,
			countersSnapshot: { ...this.counters },
			matchedEvents,
			timestamp: new Date().toISOString(),
		};
		this._restricted = true;
		this._restrictedAt = info.timestamp;
		this._quarantineInfo = info;
		this.pushEvent({ timestamp: info.timestamp, type: 'quarantine_entered', metadata: { ruleId, reason } });
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
	}

	/** Record a sensitive file read attempt. */
	recordSensitiveFileAttempt(): void {
		this.counters.sensitiveFileReadAttempts++;
	}

	/** Check if a file path targets a sensitive location. */
	isSensitivePath(path: string): boolean {
		return SENSITIVE_PATH_PATTERNS.some((p) => p.test(path));
	}

	/** Check if an HTTP action is an egress (write) attempt. */
	isEgressAction(action: string): boolean {
		return ['post', 'put', 'patch', 'delete'].includes(action);
	}

	private checkThreshold(): void {
		if (this._restricted) return;
		if (this.counters.deniedActions >= this.threshold) {
			const ts = new Date().toISOString();
			this._restricted = true;
			this._restrictedAt = ts;
			this._quarantineInfo = {
				triggerType: 'threshold',
				reason: `Denied actions (${this.counters.deniedActions}) exceeded threshold (${this.threshold})`,
				countersSnapshot: { ...this.counters },
				timestamp: ts,
			};
			this.pushEvent({ timestamp: ts, type: 'quarantine_entered', metadata: { triggerType: 'threshold' } });
		}
	}
}
