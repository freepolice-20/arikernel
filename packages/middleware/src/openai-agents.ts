/**
 * OpenAI Agents SDK middleware for Ari Kernel.
 *
 * Drop-in protection for OpenAI Agents SDK tool definitions.
 *
 * Usage:
 *
 * ```ts
 * import { protectOpenAIAgent } from "@arikernel/middleware";
 *
 * const { tools, firewall } = protectOpenAIAgent(agentTools, {
 *   preset: "safe-research",
 *   toolMappings: {
 *     web_search: { toolClass: "http", action: "get" },
 *     read_file: { toolClass: "file", action: "read" },
 *   },
 * });
 * ```
 */

import type { Firewall } from '@arikernel/runtime';
import { protectAgentTools, type AgentToolDefinition } from '@arikernel/adapters';
import {
	createMiddlewareFirewall,
	resolveToolMappings,
	type MiddlewareOptions,
} from './shared.js';

export interface OpenAIAgentMiddlewareResult {
	/** Protected tool definitions — same schema, enforced execute functions. */
	tools: AgentToolDefinition[];
	/** The firewall instance for inspection. */
	firewall: Firewall;
}

/**
 * Protect OpenAI Agents SDK tool definitions with Ari Kernel enforcement.
 *
 * Creates a firewall, resolves tool mappings, and wraps each tool's
 * `execute` function through the full security pipeline.
 *
 * ```ts
 * const { tools, firewall } = protectOpenAIAgent(myTools, {
 *   preset: "safe-research",
 * });
 *
 * // Use `tools` in your agent — enforcement is transparent.
 * ```
 */
export function protectOpenAIAgent(
	tools: AgentToolDefinition[],
	options: MiddlewareOptions = {},
): OpenAIAgentMiddlewareResult {
	const firewall = createMiddlewareFirewall(options);
	const toolNames = tools.map((t) => t.function.name);
	const mappings = resolveToolMappings(toolNames, options.toolMappings);

	// Convert to the format protectAgentTools expects
	const adapterMappings: Record<string, { toolClass: string; action: string }> = {};
	for (const [name, mapping] of Object.entries(mappings)) {
		adapterMappings[name] = { toolClass: mapping.toolClass, action: mapping.action };
	}

	const protectedTools = protectAgentTools(firewall, tools, adapterMappings);
	return { tools: protectedTools, firewall };
}
