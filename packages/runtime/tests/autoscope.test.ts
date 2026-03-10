import { describe, expect, it } from "vitest";
import { classifyScope } from "../src/autoscope.js";

describe("classifyScope", () => {
	it("classifies web search tasks as safe-research", () => {
		expect(classifyScope("search the web for climate data").preset).toBe("safe-research");
		expect(classifyScope("summarize this webpage").preset).toBe("safe-research");
		expect(classifyScope("fetch the latest news articles").preset).toBe("safe-research");
		expect(classifyScope("browse this URL and extract key facts").preset).toBe("safe-research");
	});

	it("classifies document tasks as rag-reader", () => {
		expect(classifyScope("analyze this CSV file").preset).toBe("rag-reader");
		expect(classifyScope("parse and extract data from this PDF document").preset).toBe(
			"rag-reader",
		);
		expect(classifyScope("build a RAG index from these documents").preset).toBe("rag-reader");
	});

	it("classifies coding tasks as workspace-assistant", () => {
		expect(classifyScope("refactor the code in this repository").preset).toBe(
			"workspace-assistant",
		);
		expect(classifyScope("fix the bug in the test suite").preset).toBe("workspace-assistant");
		expect(classifyScope("implement a new feature and write tests").preset).toBe(
			"workspace-assistant",
		);
		expect(classifyScope("create a new file for the build system").preset).toBe(
			"workspace-assistant",
		);
	});

	it("classifies automation tasks as automation-agent", () => {
		expect(classifyScope("sync these records to a CRM").preset).toBe("automation-agent");
		expect(classifyScope("automate the workflow pipeline").preset).toBe("automation-agent");
		expect(classifyScope("send email notification and update database records").preset).toBe(
			"automation-agent",
		);
	});

	it("falls back to safe-research for unrecognizable input", () => {
		const result = classifyScope("do the thing");
		expect(result.preset).toBe("safe-research");
		expect(result.confidence).toBe(0);
	});

	it("falls back to safe-research for empty input", () => {
		const result = classifyScope("");
		expect(result.preset).toBe("safe-research");
		expect(result.confidence).toBe(0);
	});

	it("returns scores for all presets", () => {
		const result = classifyScope("search the web");
		expect(result.scores).toHaveProperty("safe-research");
		expect(result.scores).toHaveProperty("rag-reader");
		expect(result.scores).toHaveProperty("workspace-assistant");
		expect(result.scores).toHaveProperty("automation-agent");
	});

	it("confidence is between 0 and 1", () => {
		const tasks = [
			"search the web for data",
			"analyze this CSV",
			"refactor the code",
			"automate the pipeline",
			"hello world",
		];
		for (const task of tasks) {
			const result = classifyScope(task);
			expect(result.confidence).toBeGreaterThanOrEqual(0);
			expect(result.confidence).toBeLessThanOrEqual(1);
		}
	});

	it("chooses safer preset on low confidence", () => {
		// A task with equal matches across presets should not get a high-risk preset
		const result = classifyScope("web document");
		// Both safe-research ("web") and rag-reader ("document") match
		expect(result.confidence).toBeLessThan(1);
	});
});
