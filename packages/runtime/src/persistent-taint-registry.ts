/**
 * Persistent cross-run taint tracking.
 *
 * Stores security-relevant events (sensitive reads, secret accesses, taint observations)
 * in the audit database so that subsequent runs for the same principal can inherit
 * sticky flags from prior runs. This prevents attackers from splitting attacks across
 * multiple runs to evade behavioral detection.
 *
 * At run startup, the registry queries recent persistent events and pre-seeds the
 * RunStateTracker with the appropriate sticky flags.
 */

import type { AuditStore, PersistentTaintEventRow } from "@arikernel/audit-log";
import type { RunStateTracker } from "./run-state.js";

/** Persistent taint event types recorded across runs. */
export type PersistentEventType = "sensitive_read" | "secret_access" | "egress" | "taint_observed";

export interface PersistentTaintConfig {
	/** Whether cross-run taint persistence is enabled. Default: false */
	enabled?: boolean;
	/** Retention window in milliseconds. Events older than this are ignored. Default: 24 hours */
	retentionWindowMs?: number;
	/** How often to purge expired events, in milliseconds. Default: 10 minutes */
	purgeIntervalMs?: number;
}

const DEFAULT_RETENTION_MS = 24 * 60 * 60 * 1000; // 24 hours — short TTLs allow split-run attacks

export class PersistentTaintRegistry {
	private readonly auditStore: AuditStore;
	private readonly principalId: string;
	private readonly retentionWindowMs: number;

	constructor(auditStore: AuditStore, principalId: string, config?: PersistentTaintConfig) {
		this.auditStore = auditStore;
		this.principalId = principalId;
		this.retentionWindowMs = config?.retentionWindowMs ?? DEFAULT_RETENTION_MS;
	}

	// ── Recording events ─────────────────────────────────────────────

	/** Record that a sensitive file was read during this run. */
	recordSensitiveRead(resource: string): void {
		this.auditStore.recordPersistentTaintEvent(this.principalId, "sensitive_read", resource);
	}

	/** Record that a secret/credential resource was accessed. */
	recordSecretAccess(resource?: string): void {
		this.auditStore.recordPersistentTaintEvent(this.principalId, "secret_access", resource);
	}

	/** Record an egress attempt. */
	recordEgress(resource?: string): void {
		this.auditStore.recordPersistentTaintEvent(this.principalId, "egress", resource);
	}

	/** Record a taint observation with the taint source label. */
	recordTaintObserved(taintSource: string): void {
		this.auditStore.recordPersistentTaintEvent(
			this.principalId,
			"taint_observed",
			undefined,
			taintSource,
		);
	}

	// ── Querying prior events ────────────────────────────────────────

	/** Query recent persistent events within the retention window. */
	queryRecentEvents() {
		return this.auditStore.queryPersistentTaintEvents(this.principalId, this.retentionWindowMs);
	}

	// ── Run-state initialization ─────────────────────────────────────

	/**
	 * Initialize a RunStateTracker with sticky flags from prior runs.
	 *
	 * Queries the persistent taint events for this principal within the
	 * retention window and sets the corresponding sticky flags on the tracker.
	 * This ensures that an attacker who read secrets in Run 1 cannot start
	 * a clean Run 2 and exfiltrate without triggering behavioral rules.
	 */
	initializeRunState(runState: RunStateTracker): void {
		let events: PersistentTaintEventRow[];
		try {
			events = this.queryRecentEvents();
		} catch (err) {
			// Fail open with warning: if the audit DB is unavailable, the run starts
			// without persistent taint. This is logged so operators can detect the gap.
			const msg = err instanceof Error ? err.message : String(err);
			console.error(
				`[AriKernel] Failed to load persistent taint for principal '${this.principalId}': ${msg}. Run will start without cross-run taint history.`,
			);
			return;
		}
		if (events.length === 0) return;

		for (const event of events) {
			switch (event.event_type) {
				case "sensitive_read":
					// Set the sticky flag so behavioral rules like
					// sensitive_read_then_egress can fire in the new run
					runState.seedSensitiveRead();
					break;
				case "secret_access":
					runState.seedSecretAccess();
					break;
				case "egress":
					runState.seedEgress();
					break;
				case "taint_observed":
					if (event.taint_label) {
						runState.markTainted(event.taint_label);
					}
					break;
			}
		}
	}

	// ── Maintenance ──────────────────────────────────────────────────

	/** Purge events older than the retention window. */
	purgeExpired(): number {
		return this.auditStore.purgePersistentTaintEvents(this.retentionWindowMs);
	}
}
