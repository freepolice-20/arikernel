import { afterEach, describe, expect, it } from "vitest";
import { protectCrewAITools } from "../src/crewai.js";

describe("protectCrewAITools", () => {
	let firewall: { close: () => void } | null = null;
	afterEach(() => {
		firewall?.close();
		firewall = null;
	});

	it("wraps tool execution with enforcement", async () => {
		const result = protectCrewAITools(
			{
				web_search: async (args) => `Results for: ${args.query}`,
				read_file: async (args) => `Contents of ${args.path}`,
			},
			{
				toolMappings: {
					web_search: { toolClass: "http", action: "get" },
					read_file: { toolClass: "file", action: "read" },
				},
			},
		);
		firewall = result.firewall;

		const searchResult = await result.execute("web_search", {
			url: "https://httpbin.org/get",
			query: "AI safety",
		});
		expect(searchResult).toBe("Results for: AI safety");
	});

	it("blocks denied tool calls", async () => {
		const result = protectCrewAITools(
			{
				read_file: async (args) => `Contents of ${args.path}`,
			},
			{
				toolMappings: {
					read_file: { toolClass: "file", action: "read" },
				},
			},
		);
		firewall = result.firewall;

		await expect(result.execute("read_file", { path: "~/.ssh/id_rsa" })).rejects.toThrow();
	});

	it("throws for unknown tool names", async () => {
		const result = protectCrewAITools(
			{ web_search: async () => "ok" },
			{ toolMappings: { web_search: { toolClass: "http", action: "get" } } },
		);
		firewall = result.firewall;

		await expect(result.execute("nonexistent", {})).rejects.toThrow('Unknown tool "nonexistent"');
	});

	it("lists registered tool names", async () => {
		const result = protectCrewAITools(
			{
				web_search: async () => "ok",
				read_file: async () => "ok",
			},
			{
				toolMappings: {
					web_search: { toolClass: "http", action: "get" },
					read_file: { toolClass: "file", action: "read" },
				},
			},
		);
		firewall = result.firewall;

		expect(result.toolNames).toContain("web_search");
		expect(result.toolNames).toContain("read_file");
	});

	it("passes unmapped tools through", async () => {
		const result = protectCrewAITools(
			{
				web_search: async () => "searched",
				custom: async () => "custom result",
			},
			{
				toolMappings: {
					web_search: { toolClass: "http", action: "get" },
				},
			},
		);
		firewall = result.firewall;

		const customResult = await result.execute("custom", {});
		expect(customResult).toBe("custom result");
	});
});
