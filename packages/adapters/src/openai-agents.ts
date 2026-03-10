/**
 * OpenAI Agents SDK adapter for AriKernel.
 *
 * Wraps agent tool definitions so every tool call routes through
 * AriKernel enforcement before the tool's execute function runs.
 *
 * Usage:
 *
 * ```ts
 * import { protectAgentTools } from "@arikernel/adapters/openai-agents";
 *
 * const protected = protectAgentTools(firewall, agentTools, {
 *   web_search: { toolClass: "http", action: "get" },
 *   read_file:  { toolClass: "file", action: "read" },
 * });
 * ```
 */

import type { TaintLabel, ToolResult } from "@arikernel/core";
import { ToolCallDeniedError } from "@arikernel/core";
import type { Firewall } from "@arikernel/runtime";
import { type WrapToolOptions, wrapTool } from "./adapter.js";

/** Mapping from tool name to AriKernel tool class and action. */
export interface AgentToolMapping {
	toolClass: string;
	action: string;
	taintLabels?: TaintLabel[];
}

/**
 * A tool definition compatible with the OpenAI Agents SDK.
 *
 * The SDK creates these via `tool()` with a name, description,
 * schema, and execute function.
 */
export interface AgentToolDefinition {
	type: "function";
	function: {
		name: string;
		description: string;
		parameters: Record<string, unknown>;
	};
	execute: (args: Record<string, unknown>) => Promise<string>;
}

/**
 * Wrap OpenAI Agents SDK tool definitions with AriKernel enforcement.
 *
 * Returns new tool definitions with identical schemas but protected
 * execute functions. Every call goes through capability checks, taint
 * tracking, policy evaluation, behavioral detection, and audit logging.
 *
 * Tools without a mapping entry pass through unmodified.
 *
 * @param firewall - AriKernel firewall instance
 * @param tools - Array of Agents SDK tool definitions
 * @param mappings - Map of tool name → AriKernel tool class/action
 * @returns New tool definitions with enforced execute functions
 */
export function protectAgentTools(
	firewall: Firewall,
	tools: AgentToolDefinition[],
	mappings: Record<string, AgentToolMapping>,
): AgentToolDefinition[] {
	// Register stub executors for all mapped tool classes so the
	// firewall pipeline can run (security checks + audit + taint).
	const toolClasses = new Set(Object.values(mappings).map((m) => m.toolClass));
	for (const tc of toolClasses) {
		firewall.registerExecutor({
			toolClass: tc,
			async execute(toolCall) {
				return {
					callId: toolCall.id,
					success: true,
					data: null,
					durationMs: 0,
					taintLabels: [],
				};
			},
		});
	}

	return tools.map((tool) => {
		const mapping = mappings[tool.function.name];
		if (!mapping) return tool;

		const opts: WrapToolOptions | undefined = mapping.taintLabels
			? { taintLabels: mapping.taintLabels }
			: undefined;
		const wrapped = wrapTool(firewall, mapping.toolClass, mapping.action, opts);
		const originalExecute = tool.execute;

		return {
			...tool,
			execute: async (args: Record<string, unknown>): Promise<string> => {
				// Route through firewall security pipeline
				await wrapped(args);
				// Security passed — execute the original tool function
				return originalExecute(args);
			},
		};
	});
}
