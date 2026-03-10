/**
 * AutoGen middleware for Ari Kernel.
 *
 * Drop-in protection for Microsoft AutoGen-style tool functions in
 * TypeScript orchestration layers.
 *
 * Usage:
 *
 * ```ts
 * import { protectAutoGenTools } from "@arikernel/middleware";
 *
 * const { execute, firewall } = protectAutoGenTools({
 *   web_search: async (args) => searchWeb(args.query),
 *   read_file: async (args) => readFile(args.path),
 *   run_shell: async (args) => exec(args.cmd),
 * }, {
 *   preset: "safe-research",
 * });
 *
 * await execute("web_search", { query: "AI safety" }); // ALLOWED
 * await execute("run_shell", { cmd: "rm -rf /" });      // BLOCKED
 * ```
 */

import type { Firewall } from '@arikernel/runtime';
import { wrapTool } from '@arikernel/adapters';
import {
	createMiddlewareFirewall,
	resolveToolMappings,
	registerStubExecutors,
	type MiddlewareOptions,
} from './shared.js';

/** A map of tool name → async execution function. */
export type AutoGenToolMap = Record<string, (args: Record<string, unknown>) => Promise<unknown>>;

export interface AutoGenMiddlewareResult {
	/** Execute a named tool through Ari Kernel enforcement. */
	execute: (toolName: string, args: Record<string, unknown>) => Promise<unknown>;
	/** Get all protected tool functions keyed by name. */
	tools: Record<string, (args: Record<string, unknown>) => Promise<unknown>>;
	/** List of registered tool names. */
	toolNames: string[];
	/** The firewall instance for inspection. */
	firewall: Firewall;
}

/**
 * Protect a map of AutoGen-style tool functions with Ari Kernel enforcement.
 *
 * Tool mappings are auto-inferred from common naming patterns (web_search →
 * http.get, read_file → file.read, run_shell → shell.exec). Override with
 * explicit `toolMappings` in options.
 */
export function protectAutoGenTools(
	tools: AutoGenToolMap,
	options: MiddlewareOptions = {},
): AutoGenMiddlewareResult {
	const firewall = createMiddlewareFirewall(options);
	const toolNames = Object.keys(tools);
	const mappings = resolveToolMappings(toolNames, options.toolMappings);

	registerStubExecutors(firewall, mappings, options.autoTaint);

	const protectedTools: Record<string, (args: Record<string, unknown>) => Promise<unknown>> = {};

	for (const [name, fn] of Object.entries(tools)) {
		const mapping = mappings[name];
		if (!mapping) {
			protectedTools[name] = fn;
			continue;
		}

		const guard = wrapTool(firewall, mapping.toolClass, mapping.action);
		protectedTools[name] = async (args: Record<string, unknown>) => {
			await guard(args);
			return fn(args);
		};
	}

	return {
		execute: async (toolName: string, args: Record<string, unknown>) => {
			const fn = protectedTools[toolName];
			if (!fn) {
				throw new Error(
					`Unknown tool "${toolName}". Registered: ${Object.keys(protectedTools).join(', ')}`,
				);
			}
			return fn(args);
		},
		tools: protectedTools,
		toolNames: Object.keys(protectedTools),
		firewall,
	};
}
