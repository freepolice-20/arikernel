/**
 * Structured SQLite database executor.
 *
 * A real (non-stub) database executor that connects to a SQLite database
 * and executes structured operations only. No raw SQL passthrough.
 *
 * Supported actions:
 * - `query`: SELECT rows from a table with optional WHERE conditions
 * - `mutate`: INSERT, UPDATE, or DELETE with structured parameters
 *
 * All operations use parameterized queries to prevent SQL injection.
 * Table and column names are validated against a strict allowlist pattern.
 *
 * Usage:
 * ```ts
 * import Database from "better-sqlite3";
 * import { SqliteDatabaseExecutor } from "@arikernel/tool-executors";
 *
 * const db = new Database("app.db");
 * const executor = new SqliteDatabaseExecutor(db);
 * registry.register(executor); // replaces the stub
 * ```
 */

import type { ToolCall, ToolResult } from "@arikernel/core";
import type { ToolExecutor } from "./base.js";
import { makeResult } from "./base.js";

// ── Identifier validation ────────────────────────────────────────

/**
 * Strict SQL identifier pattern: letters, digits, underscores only.
 * No dots, dashes, spaces, brackets, or quotes.
 * Max 64 chars to prevent abuse.
 */
const SAFE_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;

function isSafeIdentifier(name: string): boolean {
	return SAFE_IDENTIFIER.test(name);
}

function validateIdentifier(name: string, label: string): string | null {
	if (!name) return `${label} is required`;
	if (!isSafeIdentifier(name)) {
		return `${label} '${name}' contains invalid characters. Only letters, digits, and underscores are allowed (max 64 chars).`;
	}
	return null;
}

// ── Types ────────────────────────────────────────────────────────

/** Minimal database interface — matches better-sqlite3's synchronous API. */
export interface SqliteDatabase {
	prepare(sql: string): {
		all(...params: unknown[]): unknown[];
		run(...params: unknown[]): { changes: number; lastInsertRowid: number | bigint };
	};
}

type MutateOp = "insert" | "update" | "delete";

interface QueryParams {
	table: string;
	columns?: string[];
	where?: Record<string, unknown>;
	limit?: number;
}

interface MutateParams {
	table: string;
	op: MutateOp;
	values?: Record<string, unknown>;
	where?: Record<string, unknown>;
}

/** Max rows returned by a query to prevent memory exhaustion. */
const MAX_QUERY_ROWS = 1000;

/** Max columns in a single operation. */
const MAX_COLUMNS = 50;

// ── Executor ─────────────────────────────────────────────────────

export class SqliteDatabaseExecutor implements ToolExecutor {
	readonly toolClass = "database";

	constructor(private readonly db: SqliteDatabase) {}

	async execute(toolCall: ToolCall): Promise<ToolResult> {
		const start = Date.now();
		const { action, parameters } = toolCall;

		try {
			if (action === "query") {
				return this.executeQuery(toolCall.id, start, parameters as Record<string, unknown>);
			}
			if (action === "mutate" || action === "exec") {
				return this.executeMutate(toolCall.id, start, parameters as Record<string, unknown>);
			}
			return this.fail(
				toolCall.id,
				start,
				`Unsupported action '${action}'. Use 'query' or 'mutate'.`,
			);
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			return this.fail(toolCall.id, start, `Database error: ${msg}`);
		}
	}

	private executeQuery(callId: string, start: number, params: Record<string, unknown>): ToolResult {
		const { table, columns, where, limit } = params as unknown as QueryParams;

		// Validate table
		const tableErr = validateIdentifier(table, "table");
		if (tableErr) return this.fail(callId, start, tableErr);

		// Validate columns
		const selectedCols = columns ?? ["*"];
		if (selectedCols.length > MAX_COLUMNS) {
			return this.fail(callId, start, `Too many columns (max ${MAX_COLUMNS})`);
		}
		if (selectedCols[0] !== "*") {
			for (const col of selectedCols) {
				const colErr = validateIdentifier(col, "column");
				if (colErr) return this.fail(callId, start, colErr);
			}
		}

		// Validate WHERE keys
		const whereEntries = where ? Object.entries(where) : [];
		for (const [key] of whereEntries) {
			const keyErr = validateIdentifier(key, "where column");
			if (keyErr) return this.fail(callId, start, keyErr);
		}

		// Build parameterized query
		const colList = selectedCols.join(", ");
		let sql = `SELECT ${colList} FROM ${table}`;
		const bindParams: unknown[] = [];

		if (whereEntries.length > 0) {
			const conditions = whereEntries.map(([key]) => `${key} = ?`);
			sql += ` WHERE ${conditions.join(" AND ")}`;
			for (const [, value] of whereEntries) {
				bindParams.push(value);
			}
		}

		const rowLimit = Math.min(limit ?? MAX_QUERY_ROWS, MAX_QUERY_ROWS);
		sql += ` LIMIT ${rowLimit}`;

		const rows = this.db.prepare(sql).all(...bindParams);

		const result = makeResult(callId, true, start, {
			table,
			rows,
			rowCount: rows.length,
			limited: rows.length >= rowLimit,
		});
		return { ...result, taintLabels: [] };
	}

	private executeMutate(
		callId: string,
		start: number,
		params: Record<string, unknown>,
	): ToolResult {
		const { table, op, values, where } = params as unknown as MutateParams;

		// Validate table
		const tableErr = validateIdentifier(table, "table");
		if (tableErr) return this.fail(callId, start, tableErr);

		// Validate op
		const operation = (op ?? "insert") as MutateOp;
		if (!["insert", "update", "delete"].includes(operation)) {
			return this.fail(
				callId,
				start,
				`Unsupported mutation op '${operation}'. Use 'insert', 'update', or 'delete'.`,
			);
		}

		// Validate values
		const valueEntries = values ? Object.entries(values) : [];
		if (operation !== "delete" && valueEntries.length === 0) {
			return this.fail(callId, start, `'values' is required for '${operation}' operations`);
		}
		if (valueEntries.length > MAX_COLUMNS) {
			return this.fail(callId, start, `Too many value columns (max ${MAX_COLUMNS})`);
		}
		for (const [key] of valueEntries) {
			const keyErr = validateIdentifier(key, "value column");
			if (keyErr) return this.fail(callId, start, keyErr);
		}

		// Validate WHERE keys
		const whereEntries = where ? Object.entries(where) : [];
		if ((operation === "update" || operation === "delete") && whereEntries.length === 0) {
			return this.fail(
				callId,
				start,
				`'where' is required for '${operation}' to prevent unscoped mutations`,
			);
		}
		for (const [key] of whereEntries) {
			const keyErr = validateIdentifier(key, "where column");
			if (keyErr) return this.fail(callId, start, keyErr);
		}

		let sql: string;
		const bindParams: unknown[] = [];

		if (operation === "insert") {
			const cols = valueEntries.map(([k]) => k).join(", ");
			const placeholders = valueEntries.map(() => "?").join(", ");
			sql = `INSERT INTO ${table} (${cols}) VALUES (${placeholders})`;
			for (const [, v] of valueEntries) bindParams.push(v);
		} else if (operation === "update") {
			const setClauses = valueEntries.map(([k]) => `${k} = ?`).join(", ");
			sql = `UPDATE ${table} SET ${setClauses}`;
			for (const [, v] of valueEntries) bindParams.push(v);
			const conditions = whereEntries.map(([k]) => `${k} = ?`).join(" AND ");
			sql += ` WHERE ${conditions}`;
			for (const [, v] of whereEntries) bindParams.push(v);
		} else {
			// delete
			const conditions = whereEntries.map(([k]) => `${k} = ?`).join(" AND ");
			sql = `DELETE FROM ${table} WHERE ${conditions}`;
			for (const [, v] of whereEntries) bindParams.push(v);
		}

		const result = this.db.prepare(sql).run(...bindParams);

		const out = makeResult(callId, true, start, {
			table,
			op: operation,
			changes: result.changes,
			lastInsertRowid:
				typeof result.lastInsertRowid === "bigint"
					? Number(result.lastInsertRowid)
					: result.lastInsertRowid,
		});
		return { ...out, taintLabels: [] };
	}

	private fail(callId: string, start: number, error: string): ToolResult {
		return { ...makeResult(callId, false, start, undefined, error), taintLabels: [] };
	}
}
