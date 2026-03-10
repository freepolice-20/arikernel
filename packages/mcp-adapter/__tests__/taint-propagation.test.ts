import { now } from "@arikernel/core";
import type { TaintLabel, ToolCall } from "@arikernel/core";
import { describe, expect, it } from "vitest";
import { McpDispatchExecutor } from "../src/executor.js";
import { createTaintBridgeTool } from "../src/taint-bridge.js";

function makeTaintLabel(source: string, origin: string): TaintLabel {
	return { source, origin, confidence: 1.0, addedAt: now() };
}

describe("MCP taint propagation", () => {
	it("merges caller taint labels with inferred taints", async () => {
		const executor = new McpDispatchExecutor();
		executor.register({
			name: "fetch-page",
			async execute(args) {
				return { html: `<html>${args.url}</html>` };
			},
		});

		const callerTaint = makeTaintLabel("web", "upstream-agent");
		const toolCall: ToolCall = {
			id: "tc-1",
			runId: "run-1",
			sequence: 0,
			timestamp: now(),
			principalId: "agent-a",
			toolClass: "mcp",
			action: "fetch-page",
			parameters: { url: "https://example.com/page" },
			taintLabels: [callerTaint],
		};

		const result = await executor.execute(toolCall);
		expect(result.success).toBe(true);

		// Should contain both the caller's taint and the inferred web taint
		const sources = result.taintLabels.map((t) => t.source);
		expect(sources).toContain("web");
		// Should have upstream origin preserved
		const upstreamLabel = result.taintLabels.find((t) => t.origin === "upstream-agent");
		expect(upstreamLabel).toBeDefined();
	});

	it("deduplicates taint labels by source+origin", async () => {
		const executor = new McpDispatchExecutor();
		executor.register({
			name: "fetch",
			async execute() {
				return "ok";
			},
		});

		const toolCall: ToolCall = {
			id: "tc-2",
			runId: "run-1",
			sequence: 0,
			timestamp: now(),
			principalId: "agent-a",
			toolClass: "mcp",
			action: "fetch",
			parameters: { url: "https://example.com" },
			// Caller already has a web:example.com label — should not be duplicated
			taintLabels: [makeTaintLabel("web", "example.com")],
		};

		const result = await executor.execute(toolCall);
		const webLabels = result.taintLabels.filter(
			(t) => t.source === "web" && t.origin === "example.com",
		);
		expect(webLabels).toHaveLength(1);
	});

	it("preserves caller taint even when tool has no URL args", async () => {
		const executor = new McpDispatchExecutor();
		executor.register({
			name: "compute",
			async execute(args) {
				return { result: (args.x as number) + (args.y as number) };
			},
		});

		const toolCall: ToolCall = {
			id: "tc-3",
			runId: "run-1",
			sequence: 0,
			timestamp: now(),
			principalId: "agent-a",
			toolClass: "mcp",
			action: "compute",
			parameters: { x: 1, y: 2 },
			taintLabels: [makeTaintLabel("rag", "knowledge-base")],
		};

		const result = await executor.execute(toolCall);
		expect(result.success).toBe(true);
		const ragLabel = result.taintLabels.find((t) => t.source === "rag");
		expect(ragLabel).toBeDefined();
		expect(ragLabel?.origin).toBe("knowledge-base");
	});
});

describe("createTaintBridgeTool", () => {
	it("creates a tool that bridges taint to downstream requests", async () => {
		let capturedTaint: TaintLabel[] | undefined;

		const tool = createTaintBridgeTool({
			name: "downstream-search",
			buildRequest: (args) => ({
				toolClass: "http",
				action: "get",
				parameters: args,
			}),
			execute: async (request) => {
				capturedTaint = request.taintLabels;
				return { results: [] };
			},
		});

		const upstreamTaint = [makeTaintLabel("web", "malicious-page")];
		await tool.executeWithTaint({ query: "test" }, upstreamTaint);

		expect(capturedTaint).toBeDefined();
		expect(capturedTaint?.some((t) => t.origin === "malicious-page")).toBe(true);
	});

	it("standard execute works without taint context", async () => {
		const tool = createTaintBridgeTool({
			name: "basic-tool",
			buildRequest: (args) => ({
				toolClass: "http",
				action: "get",
				parameters: args,
			}),
			execute: async () => "ok",
		});

		const result = await tool.execute({ url: "https://example.com" });
		expect(result).toBe("ok");
	});
});
