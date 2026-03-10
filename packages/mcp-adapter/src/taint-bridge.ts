/**
 * Taint bridge for cross-firewall MCP scenarios.
 *
 * When Agent A calls an MCP tool that wraps Agent B's Firewall,
 * this bridge ensures taint from A's context propagates into B's
 * enforcement pipeline and back.
 */

import type { TaintLabel, ToolCallRequest } from "@arikernel/core";
import type { MCPTool } from "./types.js";

export interface TaintBridgeOptions {
	/** Tool name exposed via MCP. */
	name: string;
	description?: string;
	inputSchema?: Record<string, unknown>;
	/**
	 * Build a ToolCallRequest from the MCP tool arguments.
	 * The bridge injects taint labels from the upstream caller.
	 */
	buildRequest: (args: Record<string, unknown>) => ToolCallRequest;
	/**
	 * Execute the downstream request. Typically calls `firewall.execute()`.
	 * Receives the request with taint labels merged from the upstream caller.
	 */
	execute: (request: ToolCallRequest) => Promise<unknown>;
}

/**
 * Create an MCP tool that bridges taint between upstream and downstream firewalls.
 *
 * Usage:
 * ```ts
 * const tool = createTaintBridgeTool({
 *   name: 'agent-b-search',
 *   buildRequest: (args) => ({ toolClass: 'http', action: 'get', parameters: args }),
 *   execute: (req) => downstreamFirewall.execute(req),
 * });
 * mcpExecutor.register(tool);
 * ```
 */
export function createTaintBridgeTool(options: TaintBridgeOptions): MCPTool & {
	executeWithTaint: (
		args: Record<string, unknown>,
		upstreamTaint: TaintLabel[],
	) => Promise<unknown>;
} {
	return {
		name: options.name,
		description: options.description,
		inputSchema: options.inputSchema,

		// Standard MCP execute — no upstream taint context available
		async execute(args: Record<string, unknown>): Promise<unknown> {
			const request = options.buildRequest(args);
			return options.execute(request);
		},

		// Extended execute with upstream taint propagation
		async executeWithTaint(
			args: Record<string, unknown>,
			upstreamTaint: TaintLabel[],
		): Promise<unknown> {
			const request = options.buildRequest(args);
			request.taintLabels = [...(request.taintLabels ?? []), ...upstreamTaint];
			return options.execute(request);
		},
	};
}
