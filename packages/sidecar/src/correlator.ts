import type { AuditEvent } from "@arikernel/core";
import { generateId, now } from "@arikernel/core";

/**
 * Configuration for the cross-principal correlator.
 */
export interface CorrelatorConfig {
	/** Time window for correlation in milliseconds. Default: 60000 (60s). */
	windowMs?: number;
	/** Max events buffered per principal. Default: 50. */
	maxEventsPerPrincipal?: number;
}

export interface CrossPrincipalAlert {
	alertId: string;
	ruleId: string;
	severity: "low" | "medium" | "high";
	timestamp: string;
	principals: string[];
	reason: string;
	events: { principalId: string; toolClass: string; action: string; timestamp: string }[];
}

export type AlertHandler = (alert: CrossPrincipalAlert) => void;

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
		if (table) return `db:${table}`;
		const database = params?.database as string | undefined;
		if (database) return `db:${database}`;
	}
	if (toolClass === "file") {
		const path = params?.path as string | undefined;
		if (path) return `file:${path}`;
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
 */
export class CrossPrincipalCorrelator {
	private readonly windowMs: number;
	private readonly maxEvents: number;
	private readonly events = new Map<string, PrincipalEvent[]>();
	private readonly handlers: AlertHandler[] = [];

	constructor(config?: CorrelatorConfig) {
		this.windowMs = config?.windowMs ?? 60_000;
		this.maxEvents = config?.maxEventsPerPrincipal ?? 50;
	}

	/** Register an alert handler. */
	onAlert(handler: AlertHandler): void {
		this.handlers.push(handler);
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
			resourceKey: extractResourceKey(toolClass, action, params),
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

	private emit(alert: CrossPrincipalAlert): void {
		for (const handler of this.handlers) {
			try {
				handler(alert);
			} catch {
				/* handler errors must not crash correlator */
			}
		}
	}
}
