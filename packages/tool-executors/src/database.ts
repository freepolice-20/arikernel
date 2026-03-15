import type { ToolCall, ToolResult } from "@arikernel/core";
import type { ToolExecutor } from "./base.js";
import { makeResult } from "./base.js";

/**
 * MVP stub database executor.
 *
 * Validates structured parameters and audits intent but does NOT connect to
 * real databases or execute queries. Production deployments must implement a
 * custom executor with actual database adapters.
 *
 * SECURITY: Requires an explicit `table` parameter on every call so the
 * cross-principal SharedTaintRegistry can build canonical resource keys.
 * Without `table`, taint propagation across principals is impossible.
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

		// Require explicit table — the minimum structured metadata for safe scoping.
		// database-only or query-only calls are ambiguous and bypass taint tracking.
		if (!table) {
			const result = makeResult(
				toolCall.id,
				false,
				start,
				undefined,
				"Database calls require an explicit 'table' parameter. " +
					"The stub executor uses structured metadata (table, database) for " +
					"cross-principal taint tracking and policy scoping. " +
					"Raw SQL or database-only calls without 'table' are rejected.",
			);
			return { ...result, taintLabels: [] };
		}

		// MVP stub: logs intent, does not connect or execute
		const result = makeResult(toolCall.id, true, start, {
			table,
			database: database ?? undefined,
			query: query ?? undefined,
			connectionString: connectionString ? "[redacted]" : undefined,
			note: "Database executor is a stub — query was validated and audited but not executed. " +
				"Implement a custom executor for real database connectivity.",
			rows: [],
		});

		return { ...result, taintLabels: [] };
	}
}
