import { resolve } from "node:path";
import { ToolCallDeniedError } from "@arikernel/core";
import { type Firewall, createFirewall } from "@arikernel/runtime";
import { afterEach, describe, expect, it } from "vitest";
import { type AgentToolDefinition, protectAgentTools } from "../src/openai-agents.js";

const POLICY_PATH = resolve(
	import.meta.dirname,
	"..",
	"..",
	"..",
	"policies",
	"safe-defaults.yaml",
);

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
				name: "unmapped_tool",
				description: "Not mapped to AriKernel",
				parameters: { type: "object", properties: {} },
			},
			execute: async () => "unmapped result",
		},
	];
}

function makeFirewall(name: string): Firewall {
	return createFirewall({
		principal: {
			name,
			capabilities: [
				{ toolClass: "http", actions: ["get"], constraints: { allowedHosts: ["example.com"] } },
				{ toolClass: "file", actions: ["read"], constraints: { allowedPaths: ["./data/**"] } },
			],
		},
		policies: POLICY_PATH,
		auditLog: ":memory:",
	});
}

describe("protectAgentTools", () => {
	let fw: Firewall;
	afterEach(() => {
		fw?.close();
	});

	it("wraps tool execute with firewall enforcement", async () => {
		fw = makeFirewall("agents-basic");
		const tools = makeTools();
		const protected_ = protectAgentTools(fw, tools, {
			web_search: { toolClass: "http", action: "get" },
			read_file: { toolClass: "file", action: "read" },
		});

		expect(protected_).toHaveLength(3);
		// Allowed: web_search to example.com
		const result = await protected_[0].execute({ url: "https://example.com/data" });
		expect(result).toBe("Fetched: https://example.com/data");
	});

	it("denies tool call when capability is not granted", async () => {
		fw = makeFirewall("agents-deny");
		const tools = makeTools();
		const protected_ = protectAgentTools(fw, tools, {
			read_file: { toolClass: "file", action: "read" },
		});

		// read_file on sensitive path should be denied
		// biome-ignore lint/style/noNonNullAssertion: tool is defined in makeTools() above
		const readTool = protected_.find((t) => t.function.name === "read_file")!;
		await expect(readTool.execute({ path: "~/.ssh/id_rsa" })).rejects.toThrow(ToolCallDeniedError);
	});

	it("passes unmapped tools through unchanged", async () => {
		fw = makeFirewall("agents-passthrough");
		const tools = makeTools();
		const protected_ = protectAgentTools(fw, tools, {
			web_search: { toolClass: "http", action: "get" },
		});

		// biome-ignore lint/style/noNonNullAssertion: tool is defined in makeTools() above
		const unmapped = protected_.find((t) => t.function.name === "unmapped_tool")!;
		const result = await unmapped.execute({});
		expect(result).toBe("unmapped result");
	});

	it("preserves tool definition metadata", async () => {
		fw = makeFirewall("agents-metadata");
		const tools = makeTools();
		const protected_ = protectAgentTools(fw, tools, {
			web_search: { toolClass: "http", action: "get" },
		});

		// biome-ignore lint/style/noNonNullAssertion: tool is defined in makeTools() above
		const search = protected_.find((t) => t.function.name === "web_search")!;
		expect(search.type).toBe("function");
		expect(search.function.name).toBe("web_search");
		expect(search.function.description).toBe("Search the web");
	});

	it("denies tool with unknown toolClass cleanly instead of crashing", async () => {
		fw = makeFirewall("agents-unknown-class");
		const tools: AgentToolDefinition[] = [
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

		// 'email' is not a recognized toolClass — must fail closed, not crash
		const protected_ = protectAgentTools(fw, tools, {
			send_email: { toolClass: "email", action: "send" },
		});

		const emailTool = protected_[0];
		await expect(emailTool.execute({ to: "attacker@evil.com" })).rejects.toThrow(
			ToolCallDeniedError,
		);

		// Verify the error has a clean message, not a TypeError
		try {
			await emailTool.execute({ to: "test@example.com" });
		} catch (err: unknown) {
			expect(err).toBeInstanceOf(ToolCallDeniedError);
			const e = err as ToolCallDeniedError;
			expect(e.message).toContain("Unknown capability class");
			expect(e.message).toContain("email.write");
			expect(e.toolCall).toBeDefined();
			expect(e.toolCall.id).toBeTruthy();
			expect(e.toolCall.toolClass).toBe("email");
			expect(e.toolCall.action).toBe("send");
			expect(e.decision).toBeDefined();
			expect(e.decision.verdict).toBe("deny");
		}
	});

	it("never allows execution when toolClass is unknown", async () => {
		fw = makeFirewall("agents-no-allow");
		const executeSpy = { called: false };
		const tools: AgentToolDefinition[] = [
			{
				type: "function",
				function: { name: "bad_tool", description: "Test", parameters: {} },
				execute: async () => {
					executeSpy.called = true;
					return "should not run";
				},
			},
		];

		const protected_ = protectAgentTools(fw, tools, {
			bad_tool: { toolClass: "nonexistent", action: "do" },
		});

		try {
			await protected_[0].execute({});
		} catch {}
		expect(executeSpy.called).toBe(false);
	});

	it("triggers quarantine after repeated sensitive denials", async () => {
		fw = createFirewall({
			principal: {
				name: "agents-quarantine",
				capabilities: [
					{
						toolClass: "http",
						actions: ["get", "post"],
						constraints: { allowedHosts: ["example.com"] },
					},
					{ toolClass: "file", actions: ["read"], constraints: { allowedPaths: ["./data/**"] } },
				],
			},
			policies: POLICY_PATH,
			auditLog: ":memory:",
			runStatePolicy: { maxDeniedSensitiveActions: 2 },
		});

		const tools = makeTools();
		const protected_ = protectAgentTools(fw, tools, {
			read_file: { toolClass: "file", action: "read" },
			web_search: { toolClass: "http", action: "post" },
		});

		// biome-ignore lint/style/noNonNullAssertion: tool is defined in makeTools() above
		const readTool = protected_.find((t) => t.function.name === "read_file")!;

		// Trigger quarantine with sensitive file reads
		for (const path of ["~/.ssh/id_rsa", "~/.aws/credentials", "/etc/shadow"]) {
			try {
				await readTool.execute({ path });
			} catch {}
		}

		expect(fw.isRestricted).toBe(true);
	});
});
