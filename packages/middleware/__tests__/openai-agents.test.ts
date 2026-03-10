import type { AgentToolDefinition } from "@arikernel/adapters";
import { ToolCallDeniedError } from "@arikernel/core";
import { afterEach, describe, expect, it } from "vitest";
import { protectOpenAIAgent } from "../src/openai-agents.js";

function makeTools(): AgentToolDefinition[] {
	return [
		{
			type: "function",
			function: {
				name: "web_search",
				description: "Search the web",
				parameters: { type: "object", properties: { url: { type: "string" } } },
			},
			execute: async (args) => `Fetched: ${args.url}`,
		},
		{
			type: "function",
			function: {
				name: "read_file",
				description: "Read a file",
				parameters: { type: "object", properties: { path: { type: "string" } } },
			},
			execute: async (args) => `Contents of ${args.path}`,
		},
		{
			type: "function",
			function: {
				name: "send_email",
				description: "Send an email",
				parameters: { type: "object", properties: { to: { type: "string" } } },
			},
			execute: async (args) => `Sent to ${args.to}`,
		},
	];
}

describe("protectOpenAIAgent", () => {
	let firewall: { close: () => void } | null = null;
	afterEach(() => {
		firewall?.close();
		firewall = null;
	});

	it("wraps tool execute with enforcement", async () => {
		const tools = makeTools();
		const result = protectOpenAIAgent(tools, {
			toolMappings: {
				web_search: { toolClass: "http", action: "get" },
				read_file: { toolClass: "file", action: "read" },
			},
		});
		firewall = result.firewall;

		// web_search should be allowed
		const searchResult = await result.tools[0].execute({ url: "https://example.com" });
		expect(searchResult).toBe("Fetched: https://example.com");
	});

	it("preserves tool definition metadata", async () => {
		const tools = makeTools();
		const result = protectOpenAIAgent(tools, {
			toolMappings: {
				web_search: { toolClass: "http", action: "get" },
			},
		});
		firewall = result.firewall;

		expect(result.tools[0].type).toBe("function");
		expect(result.tools[0].function.name).toBe("web_search");
		expect(result.tools[0].function.description).toBe("Search the web");
	});

	it("blocks denied tool calls", async () => {
		const tools = makeTools();
		const result = protectOpenAIAgent(tools, {
			toolMappings: {
				read_file: { toolClass: "file", action: "read" },
			},
		});
		firewall = result.firewall;

		const readTool = result.tools.find((t) => t.function.name === "read_file")!;
		await expect(readTool.execute({ path: "~/.ssh/id_rsa" })).rejects.toThrow();
	});

	it("auto-infers tool mappings", async () => {
		const tools = makeTools();
		const result = protectOpenAIAgent(tools);
		firewall = result.firewall;

		// web_search auto-inferred to http.get
		const searchResult = await result.tools[0].execute({ url: "https://example.com" });
		expect(searchResult).toBe("Fetched: https://example.com");
	});

	it("returns firewall for inspection", async () => {
		const tools = makeTools();
		const result = protectOpenAIAgent(tools, {
			toolMappings: {
				web_search: { toolClass: "http", action: "get" },
			},
		});
		firewall = result.firewall;

		expect(result.firewall.runId).toBeTruthy();
		expect(result.firewall.isRestricted).toBe(false);
	});

	it("triggers quarantine after repeated sensitive denials", async () => {
		const tools = makeTools();
		const result = protectOpenAIAgent(tools, {
			toolMappings: {
				read_file: { toolClass: "file", action: "read" },
			},
		});
		firewall = result.firewall;

		const readTool = result.tools.find((t) => t.function.name === "read_file")!;
		for (const path of [
			"~/.ssh/id_rsa",
			"~/.aws/credentials",
			"/etc/shadow",
			"/root/.bashrc",
			"~/.gnupg/secring.gpg",
			"/etc/passwd",
			"~/.ssh/id_ed25519",
			"~/.ssh/config",
			"~/.bash_history",
			"/etc/shadow",
			"~/.ssh/known_hosts",
		]) {
			try {
				await readTool.execute({ path });
			} catch {}
		}

		expect(result.firewall.isRestricted).toBe(true);
	});
});
