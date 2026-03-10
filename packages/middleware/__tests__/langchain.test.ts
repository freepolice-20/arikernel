import { ToolCallDeniedError } from "@arikernel/core";
import { afterEach, describe, expect, it } from "vitest";
import {
	type LangChainTool,
	protectLangChainAgent,
	protectLangChainTools,
} from "../src/langchain.js";

function makeTools(): LangChainTool[] {
	return [
		{
			name: "web_search",
			description: "Search the web",
			func: async (args: any) => `Results for: ${args?.url ?? args}`,
		},
		{
			name: "read_file",
			description: "Read a file",
			func: async (args: any) => `Contents of ${args?.path ?? args}`,
		},
		{
			name: "custom_tool",
			description: "Unmapped tool",
			func: async () => "custom result",
		},
	];
}

describe("protectLangChainAgent", () => {
	let firewall: { close: () => void } | null = null;
	afterEach(() => {
		firewall?.close();
		firewall = null;
	});

	it("wraps tool func with firewall enforcement", async () => {
		const tools = makeTools();
		const agent = { tools };
		const result = protectLangChainAgent(agent, {
			toolMappings: {
				web_search: { toolClass: "http", action: "get" },
				read_file: { toolClass: "file", action: "read" },
			},
		});
		firewall = result.firewall;

		// web_search should be allowed (default policy allows http.get)
		const searchResult = await result.agent.tools[0].func?.({ url: "https://httpbin.org/get" });
		expect(searchResult).toBe("Results for: https://httpbin.org/get");
	});

	it("blocks tool calls that violate policy", async () => {
		const tools = makeTools();
		const agent = { tools };
		const result = protectLangChainAgent(agent, {
			toolMappings: {
				read_file: { toolClass: "file", action: "read" },
			},
		});
		firewall = result.firewall;

		// Sensitive file read should be blocked
		await expect(result.agent.tools[1].func?.({ path: "~/.ssh/id_rsa" })).rejects.toThrow();
	});

	it("passes unmapped tools through unchanged", async () => {
		const tools = makeTools();
		const agent = { tools };
		const result = protectLangChainAgent(agent, {
			toolMappings: {
				web_search: { toolClass: "http", action: "get" },
			},
		});
		firewall = result.firewall;

		// custom_tool is not mapped — should pass through
		const customResult = await result.agent.tools[2].func?.();
		expect(customResult).toBe("custom result");
	});

	it("returns the firewall for inspection", async () => {
		const tools = makeTools();
		const agent = { tools };
		const result = protectLangChainAgent(agent, {
			toolMappings: {
				web_search: { toolClass: "http", action: "get" },
			},
		});
		firewall = result.firewall;

		expect(result.firewall).toBeDefined();
		expect(result.firewall.runId).toBeTruthy();
	});

	it("auto-infers tool mappings from naming patterns", async () => {
		const tools = makeTools();
		const agent = { tools };
		// No explicit toolMappings — should auto-infer web_search and read_file
		const result = protectLangChainAgent(agent);
		firewall = result.firewall;

		// web_search auto-mapped to http.get — should work
		const searchResult = await result.agent.tools[0].func?.({ url: "https://httpbin.org/get" });
		expect(searchResult).toBe("Results for: https://httpbin.org/get");
	});

	it("wraps invoke method when present", async () => {
		const tools: LangChainTool[] = [
			{
				name: "web_search",
				invoke: async (input: any) => `Results for: ${input.url}`,
			},
		];
		const agent = { tools };
		const result = protectLangChainAgent(agent, {
			toolMappings: {
				web_search: { toolClass: "http", action: "get" },
			},
		});
		firewall = result.firewall;

		const searchResult = await result.agent.tools[0].invoke?.({ url: "https://httpbin.org/get" });
		expect(searchResult).toBe("Results for: https://httpbin.org/get");
	});

	it("supports preset configuration", async () => {
		const tools = makeTools();
		const agent = { tools };
		const result = protectLangChainAgent(agent, {
			preset: "safe-research",
			toolMappings: {
				web_search: { toolClass: "http", action: "get" },
			},
		});
		firewall = result.firewall;

		const searchResult = await result.agent.tools[0].func?.({ url: "https://httpbin.org/get" });
		expect(searchResult).toBe("Results for: https://httpbin.org/get");
	});

	it("preserves this binding for func", async () => {
		const tool: LangChainTool & { state: { called: number } } = {
			name: "web_search",
			state: { called: 0 },
			func: async function (this: any, args: any) {
				this.state.called++;
				return `called ${this.state.called}`;
			},
		};
		const agent = { tools: [tool] };
		const result = protectLangChainAgent(agent, {
			toolMappings: { web_search: { toolClass: "http", action: "get" } },
		});
		firewall = result.firewall;

		await result.agent.tools[0].func?.({ url: "https://example.com" });
		await result.agent.tools[0].func?.({ url: "https://example.com" });
		expect(tool.state.called).toBe(2);
	});

	it("preserves this binding for invoke", async () => {
		const tool: LangChainTool & { state: { called: number } } = {
			name: "web_search",
			state: { called: 0 },
			invoke: async function (this: any, input: any) {
				this.state.called++;
				return `called ${this.state.called}`;
			},
		};
		const agent = { tools: [tool] };
		const result = protectLangChainAgent(agent, {
			toolMappings: { web_search: { toolClass: "http", action: "get" } },
		});
		firewall = result.firewall;

		await result.agent.tools[0].invoke?.({ url: "https://example.com" });
		expect(tool.state.called).toBe(1);
	});
});

describe("protectLangChainTools", () => {
	let firewall: { close: () => void } | null = null;
	afterEach(() => {
		firewall?.close();
		firewall = null;
	});

	it("wraps a tool array directly", async () => {
		const tools = makeTools();
		const result = protectLangChainTools(tools, {
			toolMappings: {
				web_search: { toolClass: "http", action: "get" },
			},
		});
		firewall = result.firewall;

		const searchResult = await result.tools[0].func?.({ url: "https://httpbin.org/get" });
		expect(searchResult).toBe("Results for: https://httpbin.org/get");
	});
});
