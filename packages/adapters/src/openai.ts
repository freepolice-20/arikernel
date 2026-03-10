/**
 * OpenAI / OpenAI-style tool-calling adapter for AriKernel.
 *
 * Wraps tool execution in OpenAI-compatible agent flows so every tool call
 * routes through the firewall before reaching the actual function.
 *
 * Usage:
 *
 * ```ts
 * import { createFirewall } from "@arikernel/runtime";
 * import { protectOpenAITools } from "@arikernel/adapters/openai";
 *
 * const firewall = createFirewall({ ... });
 *
 * const tools = protectOpenAITools(firewall, {
 *   web_search: { toolClass: "http", action: "get" },
 *   read_file:  { toolClass: "file", action: "read" },
 *   run_shell:  { toolClass: "shell", action: "exec" },
 * });
 *
 * // When the model requests a tool call:
 * const result = await tools.execute("web_search", { url: "https://example.com" });
 * ```
 */
import type { TaintLabel, ToolResult } from "@arikernel/core";
import type { Firewall } from "@arikernel/runtime";
import { type WrapToolOptions, wrapTool } from "./adapter.js";

export interface ToolMapping {
	toolClass: string;
	action: string;
	taintLabels?: TaintLabel[];
}

export interface OpenAIToolSet {
	/** Execute a named tool through AriKernel enforcement. */
	execute(toolName: string, args: Record<string, unknown>): Promise<ToolResult>;

	/** Get the protected function for a specific tool. */
	getTool(toolName: string): ((args: Record<string, unknown>) => Promise<ToolResult>) | undefined;

	/** List registered tool names. */
	readonly toolNames: string[];
}

/**
 * Create a protected tool set for OpenAI-style tool calling.
 *
 * Maps tool names (as returned by the model) to AriKernel tool classes and actions.
 * Every call goes through capability checks, taint tracking, policy evaluation,
 * behavioral detection, and audit logging.
 */
export function protectOpenAITools(
	firewall: Firewall,
	mappings: Record<string, ToolMapping>,
): OpenAIToolSet {
	const tools = new Map<string, (args: Record<string, unknown>) => Promise<ToolResult>>();

	for (const [name, mapping] of Object.entries(mappings)) {
		const opts: WrapToolOptions | undefined = mapping.taintLabels
			? { taintLabels: mapping.taintLabels }
			: undefined;
		tools.set(name, wrapTool(firewall, mapping.toolClass, mapping.action, opts));
	}

	return {
		async execute(toolName: string, args: Record<string, unknown>): Promise<ToolResult> {
			const fn = tools.get(toolName);
			if (!fn) {
				throw new Error(
					`Unknown tool "${toolName}". Registered tools: ${[...tools.keys()].join(", ")}`,
				);
			}
			return fn(args);
		},

		getTool(toolName: string) {
			return tools.get(toolName);
		},

		get toolNames() {
			return [...tools.keys()];
		},
	};
}
