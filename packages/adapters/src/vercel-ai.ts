/**
 * Vercel AI SDK adapter for AriKernel.
 *
 * Wraps Vercel AI SDK tool execution so every call routes through the firewall.
 *
 * Usage:
 *
 * ```ts
 * import { createFirewall } from "@arikernel/runtime";
 * import { protectVercelTools } from "@arikernel/adapters/vercel-ai";
 *
 * const firewall = createFirewall({ ... });
 *
 * const tools = protectVercelTools(firewall, {
 *   web_search: { toolClass: "http", action: "get" },
 *   read_file:  { toolClass: "file", action: "read" },
 * });
 *
 * // Use with Vercel AI SDK's tool execution:
 * const result = await tools.execute("web_search", { url: "https://example.com" });
 * ```
 */
import type { ToolResult } from '@arikernel/core';
import type { Firewall } from '@arikernel/runtime';
import { wrapTool, type WrapToolOptions } from './adapter.js';

export interface VercelToolMapping {
	toolClass: string;
	action: string;
}

/**
 * Create protected tool executors for Vercel AI SDK tool calls.
 *
 * Returns an object with `execute(toolName, args)` that routes through AriKernel.
 * Use this in `onToolCall` or custom tool execution handlers.
 */
export function protectVercelTools(
	firewall: Firewall,
	mappings: Record<string, VercelToolMapping>,
): {
	execute(toolName: string, args: Record<string, unknown>): Promise<ToolResult>;
	toolNames: string[];
} {
	const tools = new Map<string, (args: Record<string, unknown>) => Promise<ToolResult>>();

	for (const [name, mapping] of Object.entries(mappings)) {
		tools.set(name, wrapTool(firewall, mapping.toolClass, mapping.action));
	}

	return {
		async execute(toolName: string, args: Record<string, unknown>): Promise<ToolResult> {
			const fn = tools.get(toolName);
			if (!fn) {
				throw new Error(
					`Unknown tool "${toolName}". Registered tools: ${[...tools.keys()].join(', ')}`,
				);
			}
			return fn(args);
		},

		get toolNames() {
			return [...tools.keys()];
		},
	};
}
