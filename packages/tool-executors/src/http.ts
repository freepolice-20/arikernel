import type { ToolCall, ToolResult } from '@arikernel/core';
import type { ToolExecutor } from './base.js';
import { DEFAULT_TIMEOUT_MS, makeResult } from './base.js';

export class HttpExecutor implements ToolExecutor {
	readonly toolClass = 'http';

	async execute(toolCall: ToolCall): Promise<ToolResult> {
		const start = Date.now();
		const { url, method, headers, body } = toolCall.parameters as {
			url: string;
			method?: string;
			headers?: Record<string, string>;
			body?: unknown;
		};

		const httpMethod = (method ?? toolCall.action).toUpperCase();

		try {
			const controller = new AbortController();
			const timeout = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);

			const response = await fetch(url, {
				method: httpMethod,
				headers: headers ?? undefined,
				body: body ? JSON.stringify(body) : undefined,
				signal: controller.signal,
			});

			clearTimeout(timeout);

			const contentType = response.headers.get('content-type') ?? '';
			const responseData = contentType.includes('application/json')
				? await response.json()
				: await response.text();

			const result = makeResult(toolCall.id, response.ok, start, {
				status: response.status,
				headers: Object.fromEntries(response.headers.entries()),
				body: responseData,
			});

			return { ...result, taintLabels: [] };
		} catch (err) {
			const error = err instanceof Error ? err.message : String(err);
			const result = makeResult(toolCall.id, false, start, undefined, error);
			return { ...result, taintLabels: [] };
		}
	}
}
