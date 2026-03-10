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
		expect(results[0].taintLabels).toHaveLength(1);
		expect(results[0].taintLabels[0]).toMatchObject({
			source: "web",
			origin: "example.com",
			confidence: 0.9,
		});
		expect(results[0].taintLabels[0].addedAt).toBeDefined();
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
		expect(results[0].taintLabels).toHaveLength(0);
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
		expect(results[0].taintLabels).toHaveLength(1);
		expect(results[0].taintLabels[0]).toMatchObject({
			source: "tool-output",
			origin: "database",
			confidence: 0.8,
		});
	});
});
