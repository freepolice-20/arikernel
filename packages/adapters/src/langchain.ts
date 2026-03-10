/**
 * LangChain adapter for AriKernel.
 *
 * Wraps LangChain tool execution so every call routes through the firewall.
 *
 * Usage:
 *
 * ```ts
 * import { createFirewall } from "@arikernel/runtime";
 * import { LangChainAdapter } from "@arikernel/adapters/langchain";
 *
 * const firewall = createFirewall({ ... });
 * const adapter = new LangChainAdapter(firewall);
 *
 * // Create protected tool functions for your LangChain DynamicTools
 * const httpGet = adapter.tool("http", "get");
 * const fileRead = adapter.tool("file", "read");
 *
 * // Use with LangChain DynamicTool:
 * // new DynamicTool({ name: "http_get", func: httpGet })
 * ```
 */
import type { TaintLabel, ToolResult } from "@arikernel/core";
import type { Firewall } from "@arikernel/runtime";
import { type FrameworkAdapter, type WrapToolOptions, wrapTool } from "./adapter.js";

export interface LangChainToolOptions extends WrapToolOptions {
	/** Function to derive taint labels from parameters at call time. */
	taintFrom?: (params: Record<string, unknown>) => TaintLabel[];
}

export class LangChainAdapter implements FrameworkAdapter {
	readonly framework = "langchain";
	private readonly firewall: Firewall;

	constructor(firewall: Firewall) {
		this.firewall = firewall;
	}

	/**
	 * Create a protected tool function that can be used as a LangChain DynamicTool's `func`.
	 *
	 * ```ts
	 * const adapter = new LangChainAdapter(firewall);
	 * const httpGet = adapter.tool("http", "get");
	 *
	 * new DynamicTool({
	 *   name: "http_get",
	 *   description: "Fetch a URL",
	 *   func: (input) => httpGet({ url: input }),
	 * });
	 * ```
	 */
	tool(
		toolClass: string,
		action: string,
		opts?: LangChainToolOptions,
	): (parameters: Record<string, unknown>) => Promise<ToolResult> {
		if (opts?.taintFrom) {
			const baseTool = (params: Record<string, unknown>) => {
				const dynamicTaint = opts.taintFrom?.(params);
				const mergedOpts: WrapToolOptions = {
					...opts,
					taintLabels: [...(opts.taintLabels ?? []), ...(dynamicTaint ?? [])],
				};
				return wrapTool(this.firewall, toolClass, action, mergedOpts)(params);
			};
			return baseTool;
		}

		return wrapTool(this.firewall, toolClass, action, opts);
	}

	/**
	 * Not implemented — LangChain agents don't have a single wrappable interface.
	 * Use `adapter.tool()` to wrap individual tools instead.
	 */
	protect(_agent: unknown): never {
		throw new Error(
			"LangChainAdapter.protect() is not supported. " +
				"Use adapter.tool(toolClass, action) to create protected tool functions, " +
				"then pass them to DynamicTool.",
		);
	}
}
