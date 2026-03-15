/**
 * Tests for the MVP stub DatabaseExecutor.
 *
 * Validates that incomplete structured parameters are rejected and that
 * the stub honestly reports it does not execute queries.
 */

import type { ToolCall } from "@arikernel/core";
import { describe, expect, it } from "vitest";
import { DatabaseExecutor } from "../src/database.js";

function makeToolCall(action: string, params: Record<string, unknown>): ToolCall {
	return {
		id: "test-db-1",
		toolName: "database",
		toolClass: "database",
		action,
		parameters: params,
		timestamp: new Date().toISOString(),
	};
}

describe("DatabaseExecutor stub validation", () => {
	const executor = new DatabaseExecutor();

	it("rejects query-only calls without table", async () => {
		const result = await executor.execute(makeToolCall("query", { query: "SELECT * FROM users" }));
		expect(result.success).toBe(false);
		expect(result.error).toMatch(/require.*table/i);
	});

	it("rejects database-only calls without table", async () => {
		const result = await executor.execute(
			makeToolCall("query", { database: "mydb", query: "SELECT 1" }),
		);
		expect(result.success).toBe(false);
		expect(result.error).toMatch(/require.*table/i);
	});

	it("rejects calls with no parameters at all", async () => {
		const result = await executor.execute(makeToolCall("exec", {}));
		expect(result.success).toBe(false);
		expect(result.error).toMatch(/require.*table/i);
	});

	it("accepts calls with table parameter", async () => {
		const result = await executor.execute(
			makeToolCall("query", { table: "users", query: "SELECT * FROM users" }),
		);
		expect(result.success).toBe(true);
		const data = result.data as Record<string, unknown>;
		expect(data.table).toBe("users");
		expect(data.note).toMatch(/stub/i);
		expect(data.rows).toEqual([]);
	});

	it("accepts calls with both table and database", async () => {
		const result = await executor.execute(
			makeToolCall("exec", {
				table: "orders",
				database: "shop_db",
				query: "INSERT INTO orders VALUES (1)",
			}),
		);
		expect(result.success).toBe(true);
		const data = result.data as Record<string, unknown>;
		expect(data.table).toBe("orders");
		expect(data.database).toBe("shop_db");
	});

	it("redacts connection string in output", async () => {
		const result = await executor.execute(
			makeToolCall("query", {
				table: "users",
				connectionString: "postgres://user:secret@host/db",
			}),
		);
		expect(result.success).toBe(true);
		const data = result.data as Record<string, unknown>;
		expect(data.connectionString).toBe("[redacted]");
	});

	it("stub output clearly states queries are not executed", async () => {
		const result = await executor.execute(makeToolCall("query", { table: "users" }));
		expect(result.success).toBe(true);
		const data = result.data as Record<string, unknown>;
		expect(data.note).toMatch(/not executed/i);
	});
});
