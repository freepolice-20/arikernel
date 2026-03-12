import { describe, expect, it } from "vitest";
import { Firewall } from "../src/index.js";

/**
 * Tests that constraint merging uses intersection semantics:
 * grants can only narrow the base capability, never broaden it.
 */

// biome-ignore lint/suspicious/noExplicitAny: test helper accepts varied capability shapes
function createFirewall(capabilities: any[]) {
	return new Firewall({
		principal: { name: "test-agent", capabilities },
		policies: [
			{ id: "allow-all", name: "Allow all", priority: 100, match: {}, decision: "allow" as const },
		],
		auditLog: ":memory:",
	});
}

describe("Constraint intersection semantics", () => {
	it("requested hosts are narrowed to base allowedHosts", () => {
		const fw = createFirewall([
			{ toolClass: "http", actions: ["get"], constraints: { allowedHosts: ["a.com", "b.com"] } },
		]);

		const decision = fw.requestCapability("http.read", {
			constraints: { allowedHosts: ["a.com", "evil.com"] },
		});

		expect(decision.granted).toBe(true);
		expect(decision.grant?.constraints.allowedHosts).toEqual(["a.com"]);

		fw.close();
	});

	it("base wildcard allows all requested values through", () => {
		const fw = createFirewall([
			{ toolClass: "http", actions: ["get"], constraints: { allowedHosts: ["*"] } },
		]);

		const decision = fw.requestCapability("http.read", {
			constraints: { allowedHosts: ["anything.com", "else.com"] },
		});

		expect(decision.granted).toBe(true);
		expect(decision.grant?.constraints.allowedHosts).toEqual(["anything.com", "else.com"]);

		fw.close();
	});

	it("request wildcard is narrowed to base values", () => {
		const fw = createFirewall([
			{ toolClass: "http", actions: ["get"], constraints: { allowedHosts: ["safe.com"] } },
		]);

		const decision = fw.requestCapability("http.read", {
			constraints: { allowedHosts: ["*"] },
		});

		expect(decision.granted).toBe(true);
		expect(decision.grant?.constraints.allowedHosts).toEqual(["safe.com"]);

		fw.close();
	});

	it("disjoint host sets produce empty intersection", () => {
		const fw = createFirewall([
			{ toolClass: "http", actions: ["get"], constraints: { allowedHosts: ["safe.com"] } },
		]);

		const decision = fw.requestCapability("http.read", {
			constraints: { allowedHosts: ["evil.com"] },
		});

		expect(decision.granted).toBe(true);
		expect(decision.grant?.constraints.allowedHosts).toEqual([]);

		fw.close();
	});

	it("path intersection narrows to common paths", () => {
		const fw = createFirewall([
			{
				toolClass: "file",
				actions: ["read"],
				constraints: { allowedPaths: ["./data/**", "./docs/**"] },
			},
		]);

		const decision = fw.requestCapability("file.read", {
			constraints: { allowedPaths: ["./data/**", "./secrets/**"] },
		});

		expect(decision.granted).toBe(true);
		expect(decision.grant?.constraints.allowedPaths).toEqual(["./data/**"]);

		fw.close();
	});

	it("missing request constraint inherits base constraint", () => {
		const fw = createFirewall([
			{ toolClass: "http", actions: ["get"], constraints: { allowedHosts: ["only.com"] } },
		]);

		// No constraints on the request
		const decision = fw.requestCapability("http.read");

		expect(decision.granted).toBe(true);
		expect(decision.grant?.constraints.allowedHosts).toEqual(["only.com"]);

		fw.close();
	});
});
