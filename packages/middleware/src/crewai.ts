/**
 * CrewAI middleware for Ari Kernel.
 *
 * Drop-in protection for CrewAI-style tool execution in TypeScript
 * orchestration layers.
 *
 * Usage:
 *
 * ```ts
 * import { protectCrewAITools } from "@arikernel/middleware";
 *
 * const { crew, firewall } = protectCrewAITools({
 *   web_search: async (args) => fetch(args.url).then(r => r.text()),
 *   read_file: async (args) => fs.readFile(args.path, "utf-8"),
 * }, {
 *   preset: "safe-research",
 *   toolMappings: {
 *     web_search: { toolClass: "http", action: "get" },
 *     read_file: { toolClass: "file", action: "read" },
 *   },
 * });
 *
 * // Use crew.execute("web_search", { url: "..." }) — enforced transparently.
 * ```
 */

import type { ToolResult } from '@arikernel/core';
import type { Firewall } from '@arikernel/runtime';
import { wrapTool } from '@arikernel/adapters';
import {
	createMiddlewareFirewall,
	resolveToolMappings,
	registerStubExecutors,
	type MiddlewareOptions,
} from './shared.js';

/** A map of tool name → async execution function. */
export type CrewAIToolMap = Record<string, (args: Record<string, unknown>) => Promise<unknown>>;

export interface CrewAIMiddlewareResult {
	/** Execute a named tool through Ari Kernel enforcement. */
	execute: (toolName: string, args: Record<string, unknown>) => Promise<unknown>;
	/** List of registered tool names. */
	toolNames: string[];
	/** The firewall instance for inspection. */
	firewall: Firewall;
}

/**
 * Protect a map of CrewAI-style tool functions with Ari Kernel enforcement.
 *
 * Each tool call goes through capability checks, policy evaluation, taint
 * tracking, behavioral detection, and audit logging before the original
 * function executes.
 */
export function protectCrewAITools(
	tools: CrewAIToolMap,
	options: MiddlewareOptions = {},
): CrewAIMiddlewareResult {
	const firewall = createMiddlewareFirewall(options);
	const toolNames = Object.keys(tools);
	const mappings = resolveToolMappings(toolNames, options.toolMappings);

	registerStubExecutors(firewall, mappings, options.autoTaint);

	const wrappedTools = new Map<string, (args: Record<string, unknown>) => Promise<unknown>>();

	for (const [name, fn] of Object.entries(tools)) {
		const mapping = mappings[name];
		if (!mapping) {
			// Unmapped tools pass through unprotected
			wrappedTools.set(name, fn);
			continue;
		}

		const guard = wrapTool(firewall, mapping.toolClass, mapping.action);
		wrappedTools.set(name, async (args: Record<string, unknown>) => {
			await guard(args);
			return fn(args);
		});
	}

	return {
		execute: async (toolName: string, args: Record<string, unknown>) => {
			const fn = wrappedTools.get(toolName);
			if (!fn) {
				throw new Error(
					`Unknown tool "${toolName}". Registered: ${[...wrappedTools.keys()].join(', ')}`,
				);
			}
			return fn(args);
		},
		toolNames: [...wrappedTools.keys()],
		firewall,
	};
}
