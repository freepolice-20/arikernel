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
}

const SENSITIVE_PATH_PATTERNS = [
	/\.ssh/i,
	/\.env/i,
	/\.aws/i,
	/credentials/i,
	/password/i,
	/secret/i,
];

/**
 * Cross-principal audit event correlator. Alerting only — does not block.
 *
 * Detects suspicious patterns across principal boundaries:
 * - CP-1: Principal A reads sensitive file + writes shared store → Principal B reads shared store + egresses
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
		const pe: PrincipalEvent = {
			principalId,
			toolClass: event.toolClass ?? "unknown",
			action: event.action ?? "unknown",
			timestamp: event.timestamp,
			taintSources: event.taintSources as string[] | undefined,
			params: event.parameters as Record<string, unknown> | undefined,
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
	 * A reads sensitive → writes shared → B reads shared → B egresses.
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
		const recentSharedRead = egressBuffer.find(
			(e) =>
				new Date(e.timestamp).getTime() >= cutoff &&
				((e.toolClass === "database" && e.action === "query") ||
					(e.toolClass === "file" && e.action === "read")),
		);
		if (!recentSharedRead) return;

		// Check if a DIFFERENT principal wrote to shared store after a sensitive read
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

			const hasSharedWrite = recentEvents.some(
				(e) =>
					(e.toolClass === "database" &&
						["write", "insert", "update", "create", "exec", "mutate"].includes(e.action)) ||
					(e.toolClass === "file" && e.action === "write"),
			);

			if (hasSensitiveRead && hasSharedWrite) {
				this.emit({
					alertId: generateId(),
					ruleId: "cross-principal-sensitive-exfil",
					severity: "high",
					timestamp: now(),
					principals: [pid, egressPrincipal],
					reason:
						`Principal '${pid}' read sensitive file and wrote to shared store; ` +
						`principal '${egressPrincipal}' then read from shared store and attempted egress.`,
					events: [
						...recentEvents
							.filter(
								(e) =>
									(e.toolClass === "file" && e.action === "read") ||
									(e.toolClass === "database") ||
									(e.toolClass === "file" && e.action === "write"),
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
