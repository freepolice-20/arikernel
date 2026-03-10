/**
 * LangChain middleware for Ari Kernel.
 *
 * Drop-in protection for LangChain agents — wraps tool execution so every
 * call routes through Ari Kernel's enforcement pipeline.
 *
 * Usage:
 *
 * ```ts
 * import { protectLangChainAgent } from "@arikernel/middleware";
 *
 * const protectedAgent = protectLangChainAgent(agent, {
 *   preset: "safe-research",
 * });
 * ```
 */

import { wrapTool } from "@arikernel/adapters";
import { ToolCallDeniedError } from "@arikernel/core";
import type { Firewall } from "@arikernel/runtime";
import {
	type MiddlewareOptions,
	type ToolMapping,
	createMiddlewareFirewall,
	registerStubExecutors,
	resolveToolMappings,
} from "./shared.js";

/**
 * Minimal interface for a LangChain-style tool.
 *
 * Covers DynamicTool, StructuredTool, and any object with a name + callable.
 */
export interface LangChainTool {
	name: string;
	description?: string;
	/** DynamicTool.func — primary execution path. */
	func?: (...args: any[]) => Promise<any>;
	/** StructuredTool.invoke / Runnable.invoke — alternative execution path. */
	invoke?: (input: any, config?: any) => Promise<any>;
}

/**
 * Minimal interface for a LangChain-style agent that holds tools.
 *
 * Covers AgentExecutor, RunnableAgent, or any object with a `.tools` array.
 */
export interface LangChainAgent {
	tools: LangChainTool[];
	[key: string]: unknown;
}

export interface LangChainMiddlewareResult<T> {
	/** The protected agent (same object, tools wrapped in-place). */
	agent: T;
	/** The firewall instance for inspection (quarantine status, audit, etc.). */
	firewall: Firewall;
}

/**
 * Protect a LangChain agent with Ari Kernel enforcement.
 *
 * Wraps every tool's `func` and `invoke` methods so each call routes through
 * capability checks, policy evaluation, taint tracking, behavioral detection,
 * and audit logging — transparently.
 *
 * ```ts
 * const { agent, firewall } = protectLangChainAgent(myAgent, {
 *   preset: "safe-research",
 *   toolMappings: {
 *     web_search: { toolClass: "http", action: "get" },
 *     read_file: { toolClass: "file", action: "read" },
 *   },
 * });
 * ```
 *
 * @returns The same agent with wrapped tools, plus the firewall for inspection.
 */
export function protectLangChainAgent<T extends LangChainAgent>(
	agent: T,
	options: MiddlewareOptions = {},
): LangChainMiddlewareResult<T> {
	const firewall = createMiddlewareFirewall(options);
	const toolNames = agent.tools.map((t) => t.name);
	const mappings = resolveToolMappings(toolNames, options.toolMappings);

	registerStubExecutors(firewall, mappings, options.autoTaint);

	for (const tool of agent.tools) {
		const mapping = mappings[tool.name];
		if (!mapping) continue;

		const wrapped = wrapTool(firewall, mapping.toolClass, mapping.action);

		if (tool.func) {
			const original = tool.func;
			tool.func = async (...args: any[]) => {
				const params =
					typeof args[0] === "object" && args[0] !== null ? args[0] : { input: args[0] };
				await wrapped(params);
				const result = await original.apply(tool, args);
				firewall.observeToolOutput({
					toolClass: mapping.toolClass,
					action: mapping.action,
					data: result,
				});
				return result;
			};
		}

		if (tool.invoke) {
			const original = tool.invoke;
			tool.invoke = async (input: any, config?: any) => {
				const params = typeof input === "object" && input !== null ? input : { input };
				await wrapped(params);
				const result = await original.call(tool, input, config);
				firewall.observeToolOutput({
					toolClass: mapping.toolClass,
					action: mapping.action,
					data: result,
				});
				return result;
			};
		}
	}

	return { agent, firewall };
}

/**
 * Protect an array of LangChain tools without requiring an agent object.
 *
 * ```ts
 * const { tools, firewall } = protectLangChainTools(myTools, {
 *   preset: "workspace-assistant",
 * });
 * ```
 */
export function protectLangChainTools(
	tools: LangChainTool[],
	options: MiddlewareOptions = {},
): { tools: LangChainTool[]; firewall: Firewall } {
	const agent = { tools };
	const result = protectLangChainAgent(agent, options);
	return { tools: result.agent.tools, firewall: result.firewall };
}
