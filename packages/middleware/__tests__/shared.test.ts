import { describe, expect, it } from "vitest";
import { inferToolMapping, resolveToolMappings } from "../src/shared.js";

describe("inferToolMapping", () => {
	it("maps web_search to http.get", () => {
		expect(inferToolMapping("web_search")).toEqual({ toolClass: "http", action: "get" });
	});

	it("maps read_file to file.read", () => {
		expect(inferToolMapping("read_file")).toEqual({ toolClass: "file", action: "read" });
	});

	it("maps write_file to file.write", () => {
		expect(inferToolMapping("write_file")).toEqual({ toolClass: "file", action: "write" });
	});

	it("maps run_shell to shell.exec", () => {
		expect(inferToolMapping("run_shell")).toEqual({ toolClass: "shell", action: "exec" });
	});

	it("maps query_db to database.query", () => {
		expect(inferToolMapping("query_db")).toEqual({ toolClass: "database", action: "query" });
	});

	it("maps send_email to http.post (egress)", () => {
		expect(inferToolMapping("send_email")).toEqual({ toolClass: "http", action: "post" });
	});

	it("returns null for unknown tool names", () => {
		expect(inferToolMapping("my_custom_tool")).toBeNull();
		expect(inferToolMapping("analyze_data")).toBeNull();
	});

	it("is case-insensitive", () => {
		expect(inferToolMapping("Web_Search")).toEqual({ toolClass: "http", action: "get" });
		expect(inferToolMapping("READ_FILE")).toEqual({ toolClass: "file", action: "read" });
	});
});

describe("resolveToolMappings", () => {
	it("uses explicit mappings over inference", () => {
		const result = resolveToolMappings(["web_search"], {
			web_search: { toolClass: "browser", action: "navigate" },
		});
		expect(result.web_search).toEqual({ toolClass: "browser", action: "navigate" });
	});

	it("auto-infers when no explicit mapping provided", () => {
		const result = resolveToolMappings(["web_search", "read_file"]);
		expect(result.web_search).toEqual({ toolClass: "http", action: "get" });
		expect(result.read_file).toEqual({ toolClass: "file", action: "read" });
	});

	it("omits tools that cannot be mapped", () => {
		const result = resolveToolMappings(["web_search", "custom_tool"]);
		expect(result.web_search).toBeDefined();
		expect(result.custom_tool).toBeUndefined();
	});

	it("combines explicit and inferred mappings", () => {
		const result = resolveToolMappings(["web_search", "read_file", "custom_tool"], {
			custom_tool: { toolClass: "http", action: "get" },
		});
		expect(Object.keys(result)).toHaveLength(3);
	});
});
