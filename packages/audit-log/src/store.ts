import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AuditEvent, Decision, RunContext, ToolCall, ToolResult } from '@agent-firewall/core';
import { generateId, now } from '@agent-firewall/core';
import Database from 'better-sqlite3';
import { computeHash, genesisHash } from './hash-chain.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

export class AuditStore {
	private db: Database.Database;
	private lastHash: string;
	private insertEvent: Database.Statement;
	private insertRun: Database.Statement;

	constructor(dbPath: string) {
		this.db = new Database(dbPath);
		this.db.pragma('journal_mode = WAL');
		this.db.pragma('foreign_keys = ON');
		this.runMigrations();

		this.lastHash = this.getLastHash();

		this.insertRun = this.db.prepare(`
			INSERT INTO runs (run_id, principal_id, started_at, config_json)
			VALUES (?, ?, ?, ?)
		`);

		this.insertEvent = this.db.prepare(`
			INSERT INTO events (id, run_id, sequence, timestamp, principal_id, tool_class, action,
				tool_call_json, decision_json, result_json, duration_ms, taint_sources, verdict,
				previous_hash, hash)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`);
	}

	private runMigrations(): void {
		const sqlPath = join(__dirname, 'migrations', '001-init.sql');
		let sql: string;
		try {
			sql = readFileSync(sqlPath, 'utf-8');
		} catch {
			// Fallback: try relative to source dir for dev mode
			const devPath = join(__dirname, '..', 'src', 'migrations', '001-init.sql');
			sql = readFileSync(devPath, 'utf-8');
		}
		this.db.exec(sql);
	}

	private getLastHash(): string {
		const row = this.db
			.prepare('SELECT hash FROM events ORDER BY rowid DESC LIMIT 1')
			.get() as { hash: string } | undefined;
		return row?.hash ?? genesisHash();
	}

	startRun(runId: string, principalId: string, config: Record<string, unknown>): void {
		this.insertRun.run(runId, principalId, now(), JSON.stringify(config));
	}

	endRun(runId: string): void {
		const eventCount = this.db
			.prepare('SELECT COUNT(*) as count FROM events WHERE run_id = ?')
			.get(runId) as { count: number };

		this.db
			.prepare('UPDATE runs SET ended_at = ?, event_count = ? WHERE run_id = ?')
			.run(now(), eventCount.count, runId);
	}

	append(
		toolCall: ToolCall,
		decision: Decision,
		result?: ToolResult,
	): AuditEvent {
		const id = generateId();
		const timestamp = now();
		const taintSources = decision.taintLabels.map((t) => t.source).join(',');

		const eventData = JSON.stringify({ toolCall, decision, result });
		const previousHash = this.lastHash;
		const hash = computeHash(eventData, previousHash);
		this.lastHash = hash;

		const sequence = (
			this.db
				.prepare('SELECT COALESCE(MAX(sequence), -1) + 1 as seq FROM events WHERE run_id = ?')
				.get(toolCall.runId) as { seq: number }
		).seq;

		this.insertEvent.run(
			id,
			toolCall.runId,
			sequence,
			timestamp,
			toolCall.principalId,
			toolCall.toolClass,
			toolCall.action,
			JSON.stringify(toolCall),
			JSON.stringify(decision),
			result ? JSON.stringify(result) : null,
			result?.durationMs ?? null,
			taintSources,
			decision.verdict,
			previousHash,
			hash,
		);

		return {
			id,
			runId: toolCall.runId,
			sequence,
			timestamp,
			principalId: toolCall.principalId,
			toolCall,
			decision,
			result,
			previousHash,
			hash,
		};
	}

	appendSystemEvent(
		runId: string,
		principalId: string,
		action: string,
		reason: string,
		metadata: Record<string, unknown>,
	): AuditEvent {
		const id = generateId();
		const timestamp = now();

		const toolCall: ToolCall = {
			id: generateId(),
			runId,
			sequence: 0,
			timestamp,
			principalId,
			toolClass: '_system' as any,
			action,
			parameters: metadata,
			taintLabels: [],
		};

		const decision: Decision = {
			verdict: 'deny',
			matchedRule: null,
			reason,
			taintLabels: [],
			timestamp,
		};

		const eventData = JSON.stringify({ toolCall, decision });
		const previousHash = this.lastHash;
		const hash = computeHash(eventData, previousHash);
		this.lastHash = hash;

		const sequence = (
			this.db
				.prepare('SELECT COALESCE(MAX(sequence), -1) + 1 as seq FROM events WHERE run_id = ?')
				.get(runId) as { seq: number }
		).seq;

		this.insertEvent.run(
			id, runId, sequence, timestamp, principalId,
			'_system', action,
			JSON.stringify(toolCall), JSON.stringify(decision),
			null, null, '', 'deny',
			previousHash, hash,
		);

		return {
			id, runId, sequence, timestamp, principalId,
			toolCall, decision,
			previousHash, hash,
		};
	}

	queryRun(runId: string): AuditEvent[] {
		const rows = this.db
			.prepare('SELECT * FROM events WHERE run_id = ? ORDER BY sequence')
			.all(runId) as Array<Record<string, unknown>>;

		return rows.map(rowToAuditEvent);
	}

	getRunContext(runId: string): RunContext | null {
		const row = this.db
			.prepare('SELECT * FROM runs WHERE run_id = ?')
			.get(runId) as Record<string, unknown> | undefined;

		if (!row) return null;

		return {
			runId: row.run_id as string,
			principalId: row.principal_id as string,
			startedAt: row.started_at as string,
			endedAt: (row.ended_at as string) ?? undefined,
			eventCount: row.event_count as number,
		};
	}

	listRuns(): RunContext[] {
		const rows = this.db
			.prepare('SELECT * FROM runs ORDER BY started_at DESC')
			.all() as Array<Record<string, unknown>>;

		return rows.map((row) => ({
			runId: row.run_id as string,
			principalId: row.principal_id as string,
			startedAt: row.started_at as string,
			endedAt: (row.ended_at as string) ?? undefined,
			eventCount: (row.event_count as number) ?? 0,
		}));
	}

	close(): void {
		this.db.close();
	}
}

function rowToAuditEvent(row: Record<string, unknown>): AuditEvent {
	return {
		id: row.id as string,
		runId: row.run_id as string,
		sequence: row.sequence as number,
		timestamp: row.timestamp as string,
		principalId: row.principal_id as string,
		toolCall: JSON.parse(row.tool_call_json as string),
		decision: JSON.parse(row.decision_json as string),
		result: row.result_json ? JSON.parse(row.result_json as string) : undefined,
		previousHash: row.previous_hash as string,
		hash: row.hash as string,
	};
}
