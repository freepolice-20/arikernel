/**
 * Tests for SqliteDatabaseExecutor — the real structured SQLite adapter.
 *
 * Uses better-sqlite3 in-memory databases. Tests cover:
 * - Structured query/mutate operations
 * - Identifier validation (SQL injection prevention)
 * - Adversarial inputs (path traversal in names, embedded SQL, etc.)
 * - Guardrails (row limits, required WHERE on update/delete)
 */

import type { ToolCall } from "@arikernel/core";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SqliteDatabaseExecutor } from "../src/sqlite-database.js";

function makeToolCall(action: string, params: Record<string, unknown>): ToolCall {
	return {
		id: "test-sqlite-1",
		toolName: "database",
		toolClass: "database",
		action,
		parameters: params,
		timestamp: new Date().toISOString(),
	};
}

describe("SqliteDatabaseExecutor", () => {
	let db: Database.Database;
	let executor: SqliteDatabaseExecutor;

	beforeEach(() => {
		db = new Database(":memory:");
		db.exec(`
			CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT);
			INSERT INTO users (name, email) VALUES ('alice', 'alice@example.com');
			INSERT INTO users (name, email) VALUES ('bob', 'bob@example.com');
			INSERT INTO users (name, email) VALUES ('carol', 'carol@example.com');
		`);
		executor = new SqliteDatabaseExecutor(db);
	});

	afterEach(() => {
		db.close();
	});

	// ── Basic query operations ──────────────────────────────────

	it("queries all rows from a table", async () => {
		const result = await executor.execute(makeToolCall("query", { table: "users" }));
		expect(result.success).toBe(true);
		const data = result.data as { rows: unknown[]; rowCount: number };
		expect(data.rowCount).toBe(3);
		expect(data.rows).toHaveLength(3);
	});

	it("queries with column selection", async () => {
		const result = await executor.execute(
			makeToolCall("query", { table: "users", columns: ["name"] }),
		);
		expect(result.success).toBe(true);
		const data = result.data as { rows: Array<{ name: string }> };
		expect(data.rows[0]).toEqual({ name: "alice" });
		expect(data.rows[0]).not.toHaveProperty("email");
	});

	it("queries with WHERE condition", async () => {
		const result = await executor.execute(
			makeToolCall("query", { table: "users", where: { name: "bob" } }),
		);
		expect(result.success).toBe(true);
		const data = result.data as { rows: Array<{ name: string; email: string }> };
		expect(data.rowCount).toBe(1);
		expect(data.rows[0].email).toBe("bob@example.com");
	});

	it("queries with limit", async () => {
		const result = await executor.execute(makeToolCall("query", { table: "users", limit: 1 }));
		expect(result.success).toBe(true);
		const data = result.data as { rows: unknown[]; limited: boolean };
		expect(data.rows).toHaveLength(1);
		expect(data.limited).toBe(true);
	});

	// ── Mutate operations ───────────────────────────────────────

	it("inserts a row", async () => {
		const result = await executor.execute(
			makeToolCall("mutate", {
				table: "users",
				op: "insert",
				values: { name: "dave", email: "dave@example.com" },
			}),
		);
		expect(result.success).toBe(true);
		const data = result.data as { changes: number; lastInsertRowid: number };
		expect(data.changes).toBe(1);
		expect(data.lastInsertRowid).toBe(4);

		// Verify the row was actually inserted
		const check = await executor.execute(
			makeToolCall("query", { table: "users", where: { name: "dave" } }),
		);
		expect((check.data as { rowCount: number }).rowCount).toBe(1);
	});

	it("updates a row with WHERE", async () => {
		const result = await executor.execute(
			makeToolCall("mutate", {
				table: "users",
				op: "update",
				values: { email: "alice-new@example.com" },
				where: { name: "alice" },
			}),
		);
		expect(result.success).toBe(true);
		expect((result.data as { changes: number }).changes).toBe(1);
	});

	it("deletes a row with WHERE", async () => {
		const result = await executor.execute(
			makeToolCall("mutate", {
				table: "users",
				op: "delete",
				where: { name: "carol" },
			}),
		);
		expect(result.success).toBe(true);
		expect((result.data as { changes: number }).changes).toBe(1);

		const check = await executor.execute(makeToolCall("query", { table: "users" }));
		expect((check.data as { rowCount: number }).rowCount).toBe(2);
	});

	// ── Identifier validation (SQL injection prevention) ────────

	it("rejects table name with SQL injection", async () => {
		const result = await executor.execute(
			makeToolCall("query", { table: "users; DROP TABLE users--" }),
		);
		expect(result.success).toBe(false);
		expect(result.error).toMatch(/invalid characters/i);
	});

	it("rejects table name with spaces", async () => {
		const result = await executor.execute(makeToolCall("query", { table: "users DROP" }));
		expect(result.success).toBe(false);
		expect(result.error).toMatch(/invalid characters/i);
	});

	it("rejects table name with dots (schema traversal)", async () => {
		const result = await executor.execute(makeToolCall("query", { table: "sqlite_master.type" }));
		expect(result.success).toBe(false);
		expect(result.error).toMatch(/invalid characters/i);
	});

	it("rejects table name with brackets", async () => {
		const result = await executor.execute(makeToolCall("query", { table: "[users]" }));
		expect(result.success).toBe(false);
		expect(result.error).toMatch(/invalid characters/i);
	});

	it("rejects table name with quotes", async () => {
		const result = await executor.execute(makeToolCall("query", { table: '"users"' }));
		expect(result.success).toBe(false);
		expect(result.error).toMatch(/invalid characters/i);
	});

	it("rejects table name starting with a digit", async () => {
		const result = await executor.execute(makeToolCall("query", { table: "1users" }));
		expect(result.success).toBe(false);
		expect(result.error).toMatch(/invalid characters/i);
	});

	it("rejects oversized table name (>64 chars)", async () => {
		const result = await executor.execute(makeToolCall("query", { table: "a".repeat(65) }));
		expect(result.success).toBe(false);
		expect(result.error).toMatch(/invalid characters/i);
	});

	it("rejects column name with injection", async () => {
		const result = await executor.execute(
			makeToolCall("query", { table: "users", columns: ["name; DROP TABLE users"] }),
		);
		expect(result.success).toBe(false);
		expect(result.error).toMatch(/invalid characters/i);
	});

	it("rejects WHERE key with injection", async () => {
		const result = await executor.execute(
			makeToolCall("query", {
				table: "users",
				where: { "1=1 OR name": "alice" },
			}),
		);
		expect(result.success).toBe(false);
		expect(result.error).toMatch(/invalid characters/i);
	});

	it("rejects value column name with injection in mutate", async () => {
		const result = await executor.execute(
			makeToolCall("mutate", {
				table: "users",
				op: "insert",
				values: { "name, email) VALUES ('hacker','x'); --": "ignored" },
			}),
		);
		expect(result.success).toBe(false);
		expect(result.error).toMatch(/invalid characters/i);
	});

	// ── Guardrails ──────────────────────────────────────────────

	it("rejects missing table", async () => {
		const result = await executor.execute(makeToolCall("query", {}));
		expect(result.success).toBe(false);
		expect(result.error).toMatch(/table.*required/i);
	});

	it("rejects unsupported action", async () => {
		const result = await executor.execute(makeToolCall("drop", { table: "users" }));
		expect(result.success).toBe(false);
		expect(result.error).toMatch(/unsupported action/i);
	});

	it("rejects update without WHERE (prevents unscoped update)", async () => {
		const result = await executor.execute(
			makeToolCall("mutate", {
				table: "users",
				op: "update",
				values: { email: "hacked@evil.com" },
			}),
		);
		expect(result.success).toBe(false);
		expect(result.error).toMatch(/where.*required/i);
	});

	it("rejects delete without WHERE (prevents unscoped delete)", async () => {
		const result = await executor.execute(
			makeToolCall("mutate", {
				table: "users",
				op: "delete",
			}),
		);
		expect(result.success).toBe(false);
		expect(result.error).toMatch(/where.*required/i);
	});

	it("rejects insert without values", async () => {
		const result = await executor.execute(
			makeToolCall("mutate", {
				table: "users",
				op: "insert",
			}),
		);
		expect(result.success).toBe(false);
		expect(result.error).toMatch(/values.*required/i);
	});

	it("rejects unsupported mutate op", async () => {
		const result = await executor.execute(
			makeToolCall("mutate", {
				table: "users",
				op: "truncate",
				values: {},
			}),
		);
		expect(result.success).toBe(false);
		expect(result.error).toMatch(/unsupported mutation/i);
	});

	it("handles nonexistent table gracefully", async () => {
		const result = await executor.execute(makeToolCall("query", { table: "nonexistent" }));
		expect(result.success).toBe(false);
		expect(result.error).toMatch(/database error/i);
	});

	// ── WHERE values are parameterized (not interpolated) ────────

	it("WHERE value with SQL injection is safely parameterized", async () => {
		const result = await executor.execute(
			makeToolCall("query", {
				table: "users",
				where: { name: "' OR 1=1 --" },
			}),
		);
		// Should succeed but return 0 rows (no user with that literal name)
		expect(result.success).toBe(true);
		expect((result.data as { rowCount: number }).rowCount).toBe(0);
	});

	it("INSERT values with SQL injection are safely parameterized", async () => {
		const result = await executor.execute(
			makeToolCall("mutate", {
				table: "users",
				op: "insert",
				values: { name: "'); DROP TABLE users; --", email: "evil@evil.com" },
			}),
		);
		expect(result.success).toBe(true);

		// Table still exists and has the injected string as a literal value
		const check = await executor.execute(makeToolCall("query", { table: "users" }));
		expect((check.data as { rowCount: number }).rowCount).toBe(4);
	});

	// ── exec action maps to mutate ──────────────────────────────

	it("exec action works as mutate alias", async () => {
		const result = await executor.execute(
			makeToolCall("exec", {
				table: "users",
				op: "insert",
				values: { name: "eve", email: "eve@example.com" },
			}),
		);
		expect(result.success).toBe(true);
		expect((result.data as { changes: number }).changes).toBe(1);
	});
});
