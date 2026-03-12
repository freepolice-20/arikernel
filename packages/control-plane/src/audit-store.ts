import type { DecisionVerdict, ToolClass } from "@arikernel/core";
import Database from "better-sqlite3";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS decision_audit (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	principal_id  TEXT NOT NULL,
	tool_class    TEXT NOT NULL,
	action        TEXT NOT NULL,
	decision      TEXT NOT NULL,
	reason        TEXT NOT NULL,
	timestamp     TEXT NOT NULL,
	policy_version TEXT NOT NULL,
	run_id        TEXT NOT NULL,
	signature     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_da_principal ON decision_audit(principal_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_da_decision ON decision_audit(decision, timestamp);
`;

export interface AuditRow {
	id: number;
	principal_id: string;
	tool_class: string;
	action: string;
	decision: string;
	reason: string;
	timestamp: string;
	policy_version: string;
	run_id: string;
	signature: string;
}

/**
 * SQLite-backed audit store for control plane decision events.
 *
 * Stores: principal, tool, action, decision, timestamp, policyVersion, signature.
 * WAL mode for concurrent read performance.
 */
export class ControlPlaneAuditStore {
	private readonly db: Database.Database;
	private readonly insertStmt: Database.Statement;
	private readonly queryRecentStmt: Database.Statement;
	private readonly queryByPrincipalStmt: Database.Statement;
	private readonly countStmt: Database.Statement;

	constructor(path: string) {
		this.db = new Database(path);
		if (path !== ":memory:") {
			this.db.pragma("journal_mode = WAL");
		}
		this.db.pragma("foreign_keys = ON");
		this.db.exec(SCHEMA);

		this.insertStmt = this.db.prepare(`
			INSERT INTO decision_audit
				(principal_id, tool_class, action, decision, reason, timestamp, policy_version, run_id, signature)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`);

		this.queryRecentStmt = this.db.prepare("SELECT * FROM decision_audit ORDER BY id DESC LIMIT ?");

		this.queryByPrincipalStmt = this.db.prepare(
			"SELECT * FROM decision_audit WHERE principal_id = ? ORDER BY id DESC LIMIT ?",
		);

		this.countStmt = this.db.prepare("SELECT COUNT(*) as count FROM decision_audit");
	}

	record(entry: {
		principalId: string;
		toolClass: ToolClass | string;
		action: string;
		decision: DecisionVerdict;
		reason: string;
		timestamp: string;
		policyVersion: string;
		runId: string;
		signature: string;
	}): void {
		this.insertStmt.run(
			entry.principalId,
			entry.toolClass,
			entry.action,
			entry.decision,
			entry.reason,
			entry.timestamp,
			entry.policyVersion,
			entry.runId,
			entry.signature,
		);
	}

	queryRecent(limit = 100): AuditRow[] {
		return this.queryRecentStmt.all(limit) as AuditRow[];
	}

	queryByPrincipal(principalId: string, limit = 100): AuditRow[] {
		return this.queryByPrincipalStmt.all(principalId, limit) as AuditRow[];
	}

	get count(): number {
		return (this.countStmt.get() as { count: number }).count;
	}

	/** Return all rows ordered by id ascending — for export. */
	queryAll(): AuditRow[] {
		return this.db.prepare("SELECT * FROM decision_audit ORDER BY id ASC").all() as AuditRow[];
	}

	/** Export all audit records as a JSONL string (one JSON object per line). */
	exportJsonl(): string {
		const rows = this.queryAll();
		return rows.map((row) => JSON.stringify(row)).join("\n") + (rows.length ? "\n" : "");
	}

	close(): void {
		this.db.close();
	}
}
