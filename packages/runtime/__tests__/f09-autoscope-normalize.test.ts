/**
 * F-09 regression tests: AutoScope classifyScope() must NFKC normalize
 * input before keyword matching to prevent homoglyph bypass.
 */

import { describe, expect, it } from "vitest";
import { classifyScope } from "../src/autoscope.js";

describe("F-09: AutoScope NFKC normalization", () => {
	it("matches keywords with normal ASCII input", () => {
		const result = classifyScope("Please search the web for news about AI");
		expect(result.preset).toBe("safe-research");
		expect(result.confidence).toBeGreaterThan(0);
	});

	it("matches keywords after NFKC normalization of fullwidth characters", () => {
		// Fullwidth "search" — ｓｅａｒｃｈ (U+FF53 U+FF45 U+FF41 U+FF52 U+FF43 U+FF48)
		const fullwidthSearch = "\uff53\uff45\uff41\uff52\uff43\uff48";
		const result = classifyScope(`Please ${fullwidthSearch} the web`);
		expect(result.preset).toBe("safe-research");
		expect(result.scores["safe-research"]).toBeGreaterThan(0);
	});

	it("matches keywords despite zero-width characters inserted", () => {
		// "code" with zero-width spaces: c\u200Bo\u200Bd\u200Be
		const obfuscatedCode = "c\u200Bo\u200Bd\u200Be";
		const result = classifyScope(`Please ${obfuscatedCode} a new feature`);
		expect(result.scores["workspace-assistant"]).toBeGreaterThan(0);
	});

	it("matches keywords despite bidi override characters", () => {
		// "shell" with bidi override: \u202Ashell\u202C
		const bidiShell = "\u202Ashell\u202C";
		// "automate" is the keyword we're testing for automation-agent
		const result = classifyScope(`${bidiShell} automate the workflow`);
		expect(result.scores["automation-agent"]).toBeGreaterThan(0);
	});

	it("classifies correctly with mixed normal and fullwidth text", () => {
		// Mix of normal "web" and fullwidth "ｂｒｏｗｓｅ"
		const fullwidthBrowse = "\uff42\uff52\uff4f\uff57\uff53\uff45";
		const result = classifyScope(`${fullwidthBrowse} the web for articles`);
		expect(result.preset).toBe("safe-research");
	});

	it("falls back to safe-research when no keywords match even with normalization", () => {
		const result = classifyScope("do something completely unrelated");
		expect(result.preset).toBe("safe-research");
		expect(result.confidence).toBe(0);
	});
});
