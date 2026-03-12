import { describe, expect, it } from "vitest";
import { getPreset } from "../src/presets/index.js";

describe("anti-collusion preset", () => {
	it("getPreset('anti-collusion') returns valid preset", () => {
		const preset = getPreset("anti-collusion");
		expect(preset.id).toBe("anti-collusion");
		expect(preset.name).toBe("Anti-Collusion");
		expect(preset.policies.length).toBeGreaterThan(0);
		expect(preset.capabilities.length).toBeGreaterThan(0);
		expect(preset.runStatePolicy?.behavioralRules).toBe(true);
	});

	it("preset includes both deny-derived-sensitive fragments", () => {
		const preset = getPreset("anti-collusion");
		const policyIds = preset.policies.map((p) => p.id);
		expect(policyIds).toContain("deny-derived-sensitive-egress");
		expect(policyIds).toContain("deny-derived-sensitive-shared-write");
	});

	it("derived-sensitive egress policy matches http with derived-sensitive taint", () => {
		const preset = getPreset("anti-collusion");
		const egressPolicy = preset.policies.find((p) => p.id === "deny-derived-sensitive-egress");
		expect(egressPolicy).toBeDefined();
		expect(egressPolicy?.decision).toBe("deny");
		expect(egressPolicy?.match.toolClass).toBe("http");
		expect(egressPolicy?.match.taintSources).toContain("derived-sensitive");
	});
});
