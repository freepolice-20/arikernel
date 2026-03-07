/**
 * Run-level state tracker for stateful enforcement.
 *
 * Tracks cumulative behavior counters across an entire agent run.
 * When thresholds are exceeded, the run enters "restricted mode"
 * which limits the agent to read-only safe actions.
 */

export interface RunStatePolicy {
	/** Number of denied sensitive actions before entering restricted mode. Default: 5 */
	maxDeniedSensitiveActions?: number;
}

export interface RunStateCounters {
	deniedActions: number;
	capabilityRequests: number;
	deniedCapabilityRequests: number;
	externalEgressAttempts: number;
	sensitiveFileReadAttempts: number;
}

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

	private _restricted = false;
	private _restrictedAt: string | null = null;
	private readonly threshold: number;

	constructor(policy?: RunStatePolicy) {
		this.threshold = policy?.maxDeniedSensitiveActions ?? 5;
	}

	get restricted(): boolean {
		return this._restricted;
	}

	get restrictedAt(): string | null {
		return this._restrictedAt;
	}

	/** Check if an action is allowed in restricted mode. */
	isAllowedInRestrictedMode(toolClass: string, action: string): boolean {
		return SAFE_READONLY_ACTIONS.get(toolClass)?.has(action) ?? false;
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
		if (!this._restricted && this.counters.deniedActions >= this.threshold) {
			this._restricted = true;
			this._restrictedAt = new Date().toISOString();
		}
	}
}
