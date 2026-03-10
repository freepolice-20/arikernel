import { afterEach, describe, expect, it } from "vitest";
import { protectAutoGenTools } from "../src/autogen.js";

describe("protectAutoGenTools", () => {
	let firewall: { close: () => void } | null = null;
	afterEach(() => {
		firewall?.close();
		firewall = null;
	});

	it("wraps tool execution with enforcement", async () => {
		const result = protectAutoGenTools(
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
			query: "test",
		});
		expect(searchResult).toBe("Results for: test");
	});

	it("blocks denied tool calls", async () => {
		const result = protectAutoGenTools(
			{
				run_shell: async (args) => `Output: ${args.cmd}`,
			},
			{
				toolMappings: {
					run_shell: { toolClass: "shell", action: "exec" },
				},
			},
		);
		firewall = result.firewall;

		await expect(result.execute("run_shell", { cmd: "rm -rf /" })).rejects.toThrow();
	});

	it("auto-infers tool mappings", async () => {
		const result = protectAutoGenTools({
			web_search: async (args) => `Results for: ${args.query}`,
			read_file: async (args) => `Contents of ${args.path}`,
		});
		firewall = result.firewall;

		// web_search auto-inferred → http.get
		const searchResult = await result.execute("web_search", {
			url: "https://httpbin.org/get",
			query: "test",
		});
		expect(searchResult).toBe("Results for: test");
	});

	it("exposes tools map for direct access", async () => {
		const result = protectAutoGenTools(
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

		expect(result.tools.web_search).toBeTypeOf("function");
		expect(result.tools.read_file).toBeTypeOf("function");
		expect(result.toolNames).toEqual(["web_search", "read_file"]);
	});

	it("throws for unknown tool names", async () => {
		const result = protectAutoGenTools(
			{ web_search: async () => "ok" },
			{ toolMappings: { web_search: { toolClass: "http", action: "get" } } },
		);
		firewall = result.firewall;

		await expect(result.execute("nonexistent", {})).rejects.toThrow('Unknown tool "nonexistent"');
	});

	it("returns firewall for quarantine inspection", async () => {
		const result = protectAutoGenTools(
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

		expect(result.firewall.isRestricted).toBe(false);

		// Trigger sensitive denials
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
				await result.execute("read_file", { path });
			} catch {}
		}

		expect(result.firewall.isRestricted).toBe(true);
	});
});
