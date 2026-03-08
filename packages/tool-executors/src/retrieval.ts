import type { TaintLabel, ToolCall, ToolResult } from '@arikernel/core';
import { now } from '@arikernel/core';
import type { ToolExecutor } from './base.js';
import { makeResult } from './base.js';

export class RetrievalExecutor implements ToolExecutor {
	readonly toolClass = 'retrieval';

	async execute(toolCall: ToolCall): Promise<ToolResult> {
		const start = Date.now();
		const { source, query } = toolCall.parameters as {
			source: string;
			query?: string;
		};

		// Stub: real implementation connects to a vector store or search backend.
		// The important part is that any returned data is automatically tainted.
		const result = makeResult(toolCall.id, true, start, {
			source,
			query,
			documents: [],
			note: 'Retrieval executor stub. Wire up your vector store via ExecutorRegistry.register().',
		});

		const taintLabel: TaintLabel = {
			source: 'rag',
			origin: source,
			confidence: 1.0,
			addedAt: now(),
		};

		return { ...result, taintLabels: [taintLabel] };
	}
}
