/**
 * CrewAI adapter for AriKernel.
 *
 * Provides a thin wrapper that maps CrewAI tool names to AriKernel-protected
 * tool functions. CrewAI tools are Python-based, so this adapter is designed
 * for TypeScript orchestration layers that call CrewAI-style tool functions,
 * or for the pattern where tool execution is routed through AriKernel's
 * decision server.
 *
 * Usage:
 *
 * ```ts
 * import { createFirewall } from "@arikernel/runtime";
 * import { CrewAIAdapter } from "@arikernel/adapters/crewai";
 *
 * const firewall = createFirewall({ ... });
 * const adapter = new CrewAIAdapter(firewall);
 *
 * adapter.register("search_tool", "http", "get");
 * adapter.register("file_reader", "file", "read");
 *
 * // When a CrewAI agent calls a tool:
 * const result = await adapter.execute("search_tool", { url: "https://example.com" });
 * ```
 */
import type { TaintLabel, ToolResult } from "@arikernel/core";
import type { Firewall } from "@arikernel/runtime";
import { type FrameworkAdapter, type WrapToolOptions, wrapTool } from "./adapter.js";

export interface CrewAIToolRegistration {
	toolClass: string;
	action: string;
	taintLabels?: TaintLabel[];
}

export class CrewAIAdapter implements FrameworkAdapter {
	readonly framework = "crewai";
	private readonly firewall: Firewall;
	private readonly tools = new Map<
		string,
		(args: Record<string, unknown>) => Promise<ToolResult>
	>();

	constructor(firewall: Firewall) {
		this.firewall = firewall;
	}

	/**
	 * Register a CrewAI tool name with its AriKernel tool class and action.
	 */
	register(toolName: string, toolClass: string, action: string, opts?: WrapToolOptions): this {
		this.tools.set(toolName, wrapTool(this.firewall, toolClass, action, opts));
		return this;
	}

	/**
	 * Execute a registered tool through AriKernel enforcement.
	 */
	async execute(toolName: string, args: Record<string, unknown>): Promise<ToolResult> {
		const fn = this.tools.get(toolName);
		if (!fn) {
			throw new Error(
				`Unknown CrewAI tool "${toolName}". ` + `Registered: ${[...this.tools.keys()].join(", ")}`,
			);
		}
		return fn(args);
	}

	/** List registered tool names. */
	get toolNames(): string[] {
		return [...this.tools.keys()];
	}

	/**
	 * Not applicable — CrewAI agents are Python objects.
	 * Use `register()` + `execute()` instead.
	 */
	protect(_agent: unknown): never {
		throw new Error(
			"CrewAIAdapter.protect() is not supported. " +
				"Use adapter.register(name, toolClass, action) to register tools, " +
				"then adapter.execute(name, args) to call them through AriKernel.",
		);
	}
}
