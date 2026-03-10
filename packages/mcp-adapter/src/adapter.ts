import type { Firewall } from "@arikernel/runtime";
import { McpDispatchExecutor } from "./executor.js";
import type { MCPAdapter, MCPTool } from "./types.js";

/**
 * Wrap a set of MCP tools with AriKernel enforcement.
 *
 * Every callTool() invocation passes through the full AriKernel pipeline:
 * capability token check → taint/provenance check → policy evaluation →
 * behavioral rule evaluation → audit log append.
 *
 * @param firewall - An initialised AriKernel Firewall instance.
 * @param tools    - MCP tools to register and protect.
 * @returns        - A mediated MCPAdapter ({ callTool, listTools }).
 *
 * @example
 * ```ts
 * const fw = createFirewall({ ... });
 * const mcp = protectMCPTools(fw, [searchTool, fetchTool]);
 * const result = await mcp.callTool('web_search', { query: 'hello' });
 * ```
 */
export function protectMCPTools(firewall: Firewall, tools: MCPTool[]): MCPAdapter {
	const executor = new McpDispatchExecutor();
	for (const tool of tools) {
		executor.register(tool);
	}
	firewall.registerExecutor(executor);

	return {
		async callTool(name: string, args: Record<string, unknown>): Promise<unknown> {
			const result = await firewall.execute({
				toolClass: "mcp",
				action: name,
				parameters: args,
			});

			if (!result.success) {
				throw new Error(result.error ?? `MCP tool '${name}' call denied`);
			}

			return result.data;
		},

		listTools(): Array<Omit<MCPTool, "execute">> {
			return executor.list();
		},
	};
}
