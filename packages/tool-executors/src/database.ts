import type { ToolCall, ToolResult } from '@arikernel/core';
import type { ToolExecutor } from './base.js';
import { makeResult } from './base.js';

export class DatabaseExecutor implements ToolExecutor {
	readonly toolClass = 'database';

	async execute(toolCall: ToolCall): Promise<ToolResult> {
		const start = Date.now();
		const { query, connectionString } = toolCall.parameters as {
			query: string;
			connectionString?: string;
		};

		// MVP: stub executor that logs intent but does not connect
		// Real implementation will support SQLite, Postgres via adapters
		const result = makeResult(toolCall.id, true, start, {
			query,
			connectionString: connectionString ? '[redacted]' : undefined,
			note: 'Database executor is a stub in MVP. Query was validated but not executed.',
			rows: [],
		});

		return { ...result, taintLabels: [] };
	}
}
