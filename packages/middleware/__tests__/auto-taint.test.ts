import type { ToolResult } from "@arikernel/core";
import { afterEach, describe, expect, it } from "vitest";
import { protectAutoGenTools } from "../src/autogen.js";

describe("autoTaint option", () => {
	let firewall: { close: () => void } | null = null;
	afterEach(() => {
		firewall?.close();
		firewall = null;
	});

	it("adds web taint labels for HTTP tools when autoTaint is true", async () => {
		const results: ToolResult[] = [];
		const { execute, firewall: fw } = protectAutoGenTools(
			{
				web_search: async (args) => `Results for: ${args.query}`,
			},
			{
				autoTaint: true,
				toolMappings: {
					web_search: { toolClass: "http", action: "get" },
				},
				hooks: {
					onExecute: (_tc, result) => {
						results.push(result);
					},
				},
			},
		);
		firewall = fw;

		await execute("web_search", { url: "https://example.com/search", query: "test" });

		expect(results).toHaveLength(1);
		// Pipeline always adds model-generated taint + auto-taint adds web taint
		expect(
			results[0].taintLabels.some((l) => l.source === "web" && l.origin === "example.com"),
		).toBe(true);
		expect(results[0].taintLabels.some((l) => l.source === "model-generated")).toBe(true);
	});

	it("returns empty taint labels when autoTaint is false", async () => {
		const results: ToolResult[] = [];
		const { execute, firewall: fw } = protectAutoGenTools(
			{
				web_search: async (args) => `Results for: ${args.query}`,
			},
			{
				autoTaint: false,
				toolMappings: {
					web_search: { toolClass: "http", action: "get" },
				},
				hooks: {
					onExecute: (_tc, result) => {
						results.push(result);
					},
				},
			},
		);
		firewall = fw;

		await execute("web_search", { url: "https://example.com/search", query: "test" });

		expect(results).toHaveLength(1);
		// autoTaint=false means no explicit web/tool-output taint added by middleware,
		// but pipeline always injects model-generated taint for all tool calls
		expect(results[0].taintLabels.some((l) => l.source === "model-generated")).toBe(true);
		expect(results[0].taintLabels.some((l) => l.source === "web")).toBe(false);
	});

	it("adds database taint labels for database tools", async () => {
		const results: ToolResult[] = [];
		const { execute, firewall: fw } = protectAutoGenTools(
			{
				query_db: async (args) => `rows: ${args.sql}`,
			},
			{
				autoTaint: true,
				allow: { http: true, file: true, shell: false, database: true },
				toolMappings: {
					query_db: { toolClass: "database", action: "query" },
				},
				hooks: {
					onExecute: (_tc, result) => {
						results.push(result);
					},
				},
			},
		);
		firewall = fw;

		await execute("query_db", { sql: "SELECT 1" });

		expect(results).toHaveLength(1);
		// Pipeline adds model-generated taint + auto-taint adds tool-output taint
		expect(
			results[0].taintLabels.some((l) => l.source === "tool-output" && l.origin === "database"),
		).toBe(true);
		expect(results[0].taintLabels.some((l) => l.source === "model-generated")).toBe(true);
	});
});
