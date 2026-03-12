import { PRESETS, getPreset } from "@arikernel/core";
import { afterEach, describe, expect, it } from "vitest";
import { protectCrewAITools } from "../src/crewai.js";
import { type LangChainTool, protectLangChainTools } from "../src/langchain.js";

describe("preset loading", () => {
	it("loads safe preset with correct runStatePolicy", () => {
		const preset = getPreset("safe");
		expect(preset.id).toBe("safe");
		expect(preset.runStatePolicy).toEqual({
			maxDeniedSensitiveActions: 5,
			behavioralRules: true,
		});
	});

	it("loads strict preset with low threshold", () => {
		const preset = getPreset("strict");
		expect(preset.id).toBe("strict");
		expect(preset.runStatePolicy?.maxDeniedSensitiveActions).toBe(3);
	});

	it("loads research preset with high threshold", () => {
		const preset = getPreset("research");
		expect(preset.id).toBe("research");
		expect(preset.runStatePolicy?.maxDeniedSensitiveActions).toBe(20);
	});

	it("throws for unknown preset", () => {
		expect(() => getPreset("nonexistent" as string)).toThrow("Unknown preset");
	});

	it("all 8 presets are available", () => {
		const ids = Object.keys(PRESETS);
		expect(ids).toContain("safe");
		expect(ids).toContain("strict");
		expect(ids).toContain("research");
		expect(ids).toContain("safe-research");
		expect(ids).toContain("rag-reader");
		expect(ids).toContain("workspace-assistant");
		expect(ids).toContain("automation-agent");
		expect(ids).toContain("anti-collusion");
		expect(ids).toHaveLength(8);
	});

	it("safe preset has correct capabilities", () => {
		const preset = getPreset("safe");
		const toolClasses = preset.capabilities.map((c) => c.toolClass);
		expect(toolClasses).toContain("http");
		expect(toolClasses).toContain("file");
		expect(toolClasses).toContain("database");
		expect(toolClasses).not.toContain("shell");
	});

	it("strict preset has empty host allowlist", () => {
		const preset = getPreset("strict");
		const httpCap = preset.capabilities.find((c) => c.toolClass === "http");
		expect(httpCap?.constraints?.allowedHosts).toEqual([]);
	});

	it("research preset includes shell capability", () => {
		const preset = getPreset("research");
		const toolClasses = preset.capabilities.map((c) => c.toolClass);
		expect(toolClasses).toContain("shell");
	});
});

describe("middleware preset integration", () => {
	let firewall: { close: () => void } | null = null;
	afterEach(() => {
		firewall?.close();
		firewall = null;
	});

	it("creates firewall with safe preset", () => {
		const tools: LangChainTool[] = [{ name: "web_search", func: async () => "ok" }];
		const result = protectLangChainTools(tools, { preset: "safe" });
		firewall = result.firewall;
		expect(result.firewall).toBeDefined();
		expect(result.firewall.runId).toBeTruthy();
	});

	it("creates firewall with strict preset", () => {
		const result = protectCrewAITools(
			{ web_search: async () => "ok" },
			{ preset: "strict", toolMappings: { web_search: { toolClass: "http", action: "get" } } },
		);
		firewall = result.firewall;
		expect(result.firewall).toBeDefined();
	});

	it("creates firewall with research preset", () => {
		const tools: LangChainTool[] = [{ name: "web_search", func: async () => "ok" }];
		const result = protectLangChainTools(tools, { preset: "research" });
		firewall = result.firewall;
		expect(result.firewall).toBeDefined();
	});

	it("custom allow overrides preset", () => {
		const tools: LangChainTool[] = [
			{
				name: "web_search",
				func: async (args: unknown) => `Results for: ${(args as Record<string, string>).url}`,
			},
		];
		const result = protectLangChainTools(tools, {
			allow: {
				capabilities: [
					{ toolClass: "http", actions: ["get"], constraints: { allowedHosts: ["example.com"] } },
				],
			},
		});
		firewall = result.firewall;
		expect(result.firewall).toBeDefined();
	});
});
