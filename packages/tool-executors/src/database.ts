import type { ToolCall, ToolResult } from "@arikernel/core";
import type { ToolExecutor } from "./base.js";
import { makeResult } from "./base.js";

/**
 * SECURITY: Require structured database parameters (table, database) rather than
 * allowing raw SQL strings. Raw SQL bypasses cross-principal shared-store tracking
 * because the SharedTaintRegistry relies on explicit table/database fields to
 * identify shared resources. Without structured params, taint propagation fails.
 */

export class DatabaseExecutor implements ToolExecutor {
	readonly toolClass = "database";

	async execute(toolCall: ToolCall): Promise<ToolResult> {
		const start = Date.now();
		const { table, database, query, connectionString } = toolCall.parameters as {
			table?: string;
			database?: string;
			query?: string;
			connectionString?: string;
		};

		// SECURITY: Require explicit table field for cross-principal taint tracking.
		// Raw SQL-only queries bypass SharedTaintRegistry resource key extraction.
		if (!table) {
			if (query && !database) {
				const result = makeResult(toolCall.id, false, start, undefined,
					"Database calls require an explicit 'table' parameter for cross-principal " +
					"taint tracking. Raw SQL without structured metadata is rejected. " +
					"Provide { table: 'name', ... } in parameters.",
				);
				return { ...result, taintLabels: [] };
			}
		}

		// MVP: stub executor that logs intent but does not connect
		// Real implementation will support SQLite, Postgres via adapters
		const result = makeResult(toolCall.id, true, start, {
			table,
			database,
			query: query ?? undefined,
			connectionString: connectionString ? "[redacted]" : undefined,
			note: "Database executor is a stub in MVP. Query was validated but not executed.",
			rows: [],
		});

		return { ...result, taintLabels: [] };
	}
}
