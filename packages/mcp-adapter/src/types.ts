/**
 * Minimal MCP tool interface. Compatible with the Model Context Protocol tool
 * shape but without requiring the full MCP SDK as a dependency.
 */
export interface MCPTool {
	/** Unique tool name (used as the `action` in AriKernel tool calls). */
	name: string;
	description?: string;
	/** JSON Schema describing the tool's input arguments. */
	inputSchema?: Record<string, unknown>;
	/** The actual implementation. Throw to signal failure. */
	execute(args: Record<string, unknown>): Promise<unknown>;
}

/** Returned by protectMCPTools — the mediated MCP surface. */
export interface MCPAdapter {
	/** Call a tool by name. Throws if the call is denied or the tool errors. */
	callTool(name: string, args: Record<string, unknown>): Promise<unknown>;
	/** List registered tools (name, description, inputSchema — no execute). */
	listTools(): Array<Omit<MCPTool, "execute">>;
}
