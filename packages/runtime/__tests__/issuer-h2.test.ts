import type { CapabilityClass, CapabilityRequest, Principal, TaintLabel } from "@arikernel/core";
import { generateId, now } from "@arikernel/core";
import { PolicyEngine } from "@arikernel/policy-engine";
import { TaintTracker } from "@arikernel/taint-tracker";
import { describe, expect, it } from "vitest";
import { CapabilityIssuer } from "../src/issuer.js";
import { TokenStore } from "../src/token-store.js";

function makePrincipal(): Principal {
	return {
		id: generateId(),
		name: "test-agent",
		capabilities: [
			{ toolClass: "http", actions: ["get", "post", "put", "delete"] },
			{ toolClass: "shell", actions: ["exec"] },
			{ toolClass: "file", actions: ["read", "write"] },
		],
	};
}

function makeRequest(capClass: string, taint: TaintLabel[] = []): CapabilityRequest {
	return {
		id: generateId(),
		principalId: "test",
		capabilityClass: capClass as CapabilityClass,
		constraints: {},
		taintLabels: taint,
		justification: "test",
		timestamp: now(),
	};
}

const webTaint: TaintLabel[] = [{ source: "web", origin: "https://evil.com", confidence: 1 }];

describe("H2: http.write denied when tainted", () => {
	it("denies http.write with untrusted taint", () => {
		const policy = new PolicyEngine([
			{ id: "allow-all", name: "Allow all", priority: 100, match: {}, decision: "allow" as const },
		]);
		const taint = new TaintTracker();
		const store = new TokenStore();
		const issuer = new CapabilityIssuer(policy, taint, store);

		const result = issuer.evaluate(makeRequest("http.write", webTaint), makePrincipal());
		expect(result.granted).toBe(false);
		expect(result.reason).toContain("untrusted taint");
	});

	it("allows http.write without taint", () => {
		const policy = new PolicyEngine([
			{ id: "allow-all", name: "Allow all", priority: 100, match: {}, decision: "allow" as const },
		]);
		const taint = new TaintTracker();
		const store = new TokenStore();
		const issuer = new CapabilityIssuer(policy, taint, store);

		const result = issuer.evaluate(makeRequest("http.write", []), makePrincipal());
		expect(result.granted).toBe(true);
	});

	it("allows http.read even with taint (not in sensitive list)", () => {
		const policy = new PolicyEngine([
			{ id: "allow-all", name: "Allow all", priority: 100, match: {}, decision: "allow" as const },
		]);
		const taint = new TaintTracker();
		const store = new TokenStore();
		const issuer = new CapabilityIssuer(policy, taint, store);

		const result = issuer.evaluate(makeRequest("http.read", webTaint), makePrincipal());
		expect(result.granted).toBe(true);
	});
});
