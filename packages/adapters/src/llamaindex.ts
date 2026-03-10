/**
 * LlamaIndex (TypeScript) adapter for AriKernel.
 *
 * Wraps LlamaIndex tool functions so every call routes through
 * AriKernel enforcement before reaching the actual tool implementation.
 *
 * Usage:
 *
 * ```ts
 * import { LlamaIndexAdapter } from "@arikernel/adapters/llamaindex";
 *
 * const adapter = new LlamaIndexAdapter(firewall);
 *
 * // Wrap individual tool functions
 * const protectedFetch = adapter.tool("http", "get");
 * const protectedRead  = adapter.tool("file", "read");
 *
 * // Use in LlamaIndex FunctionTool.from()
 * const fetchTool = FunctionTool.from(
 *   (params) => protectedFetch(params),
 *   { name: "fetch_url", description: "Fetch a URL" }
 * );
 * ```
 */

import type { TaintLabel, ToolResult } from "@arikernel/core";
import type { Firewall } from "@arikernel/runtime";
import { type ProtectedTool, type WrapToolOptions, wrapTool } from "./adapter.js";

/** Options for wrapping a LlamaIndex tool. */
export interface LlamaIndexToolOptions extends WrapToolOptions {
	/** Dynamic taint derivation based on tool parameters. */
	taintFrom?: (params: Record<string, unknown>) => TaintLabel[];
}

/** Mapping from tool name to AriKernel tool class and action. */
export interface LlamaIndexToolMapping {
	toolClass: string;
	action: string;
	taintLabels?: TaintLabel[];
	taintFrom?: (params: Record<string, unknown>) => TaintLabel[];
}

/**
 * LlamaIndex adapter for AriKernel.
 *
 * Provides tool wrapping compatible with LlamaIndex TS's FunctionTool pattern.
 * Each wrapped tool routes through the full enforcement pipeline:
 * capability checks, taint tracking, policy evaluation, behavioral rules.
 */
export class LlamaIndexAdapter {
	readonly framework = "llamaindex";
	private readonly firewall: Firewall;

	constructor(firewall: Firewall) {
		this.firewall = firewall;
	}

	/**
	 * Create a protected tool function for a given tool class and action.
	 *
	 * Returns a function suitable for use with LlamaIndex's FunctionTool.from().
	 */
	tool(toolClass: string, action: string, opts?: LlamaIndexToolOptions): ProtectedTool {
		if (opts?.taintFrom) {
			const taintFrom = opts.taintFrom;
			return (params: Record<string, unknown>) => {
				const dynamicTaint = taintFrom(params);
				const mergedOpts: WrapToolOptions = {
					...opts,
					taintLabels: [...(opts.taintLabels ?? []), ...dynamicTaint],
				};
				return wrapTool(this.firewall, toolClass, action, mergedOpts)(params);
			};
		}
		return wrapTool(this.firewall, toolClass, action, opts);
	}

	/**
	 * Protect multiple tools at once from a mapping.
	 *
	 * Returns a map of tool name → protected function.
	 */
	protectTools(mappings: Record<string, LlamaIndexToolMapping>): Record<string, ProtectedTool> {
		const result: Record<string, ProtectedTool> = {};
		for (const [name, mapping] of Object.entries(mappings)) {
			result[name] = this.tool(mapping.toolClass, mapping.action, {
				taintLabels: mapping.taintLabels,
				taintFrom: mapping.taintFrom,
			});
		}
		return result;
	}
}
