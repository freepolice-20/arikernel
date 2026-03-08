import type { TaintLabel, ToolCall, ToolResult } from '@arikernel/core';
import { now } from '@arikernel/core';
import type { ToolExecutor } from '@arikernel/tool-executors';
import type { MCPTool } from './types.js';

/**
 * Infer taint labels from MCP tool arguments.
 *
 * - args containing `url` / `endpoint` → web:<hostname>
 * - args containing `source` / `collection` → rag:<value>
 * - everything else → tool-output provenance label
 */
function inferTaintLabels(args: Record<string, unknown>): TaintLabel[] {
	const labels: TaintLabel[] = [];
	const ts = now();

	const urlArg = args['url'] ?? args['endpoint'];
	if (typeof urlArg === 'string') {
		try {
			const hostname = new URL(urlArg).hostname;
			labels.push({ source: 'web', origin: hostname, confidence: 1.0, addedAt: ts });
		} catch {
			labels.push({ source: 'web', origin: urlArg, confidence: 0.8, addedAt: ts });
		}
	}

	const ragArg = args['source'] ?? args['collection'];
	if (typeof ragArg === 'string') {
		labels.push({ source: 'rag', origin: ragArg, confidence: 1.0, addedAt: ts });
	}

	if (labels.length === 0) {
		labels.push({ source: 'tool-output', origin: 'mcp', confidence: 1.0, addedAt: ts });
	}

	return labels;
}

/**
 * Dispatches AriKernel tool calls with toolClass='mcp' to registered MCPTools.
 * The `action` field maps to the tool name.
 */
export class McpDispatchExecutor implements ToolExecutor {
	readonly toolClass = 'mcp';

	private tools = new Map<string, MCPTool>();

	register(tool: MCPTool): void {
		this.tools.set(tool.name, tool);
	}

	has(name: string): boolean {
		return this.tools.has(name);
	}

	list(): Array<Omit<MCPTool, 'execute'>> {
		return Array.from(this.tools.values()).map(({ name, description, inputSchema }) => ({
			name,
			description,
			inputSchema,
		}));
	}

	async execute(toolCall: ToolCall): Promise<ToolResult> {
		const start = Date.now();
		const tool = this.tools.get(toolCall.action);

		if (!tool) {
			return {
				callId: toolCall.id,
				success: false,
				error: `Unknown MCP tool: '${toolCall.action}'. Registered tools: [${[...this.tools.keys()].join(', ')}]`,
				taintLabels: [],
				durationMs: Date.now() - start,
			};
		}

		try {
			const data = await tool.execute(toolCall.parameters);
			const taintLabels = inferTaintLabels(toolCall.parameters);
			return {
				callId: toolCall.id,
				success: true,
				data,
				taintLabels,
				durationMs: Date.now() - start,
			};
		} catch (err) {
			return {
				callId: toolCall.id,
				success: false,
				error: err instanceof Error ? err.message : String(err),
				taintLabels: [],
				durationMs: Date.now() - start,
			};
		}
	}
}
