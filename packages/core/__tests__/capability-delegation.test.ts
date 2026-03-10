import { describe, expect, it } from "vitest";
import {
	type DelegatedCapability,
	createDelegatedPrincipal,
	delegateCapability,
	revokeDelegationsFrom,
	validateDelegationChain,
} from "../src/capability-delegation.js";
import type { Capability, Principal } from "../src/types/principal.js";

describe("delegateCapability", () => {
	const parentId = "parent-001";
	const childId = "child-001";

	it("narrows actions to the intersection", () => {
		const parent: DelegatedCapability = {
			toolClass: "http",
			actions: ["get", "head", "post"],
		};
		const request: Capability = {
			toolClass: "http",
			actions: ["get", "post", "delete"],
		};

		const result = delegateCapability(parent, request, parentId, childId);

		expect(result.granted).toBe(true);
		expect(result.capability?.actions).toEqual(["get", "post"]);
	});

	it("narrows constraints to the intersection", () => {
		const parent: DelegatedCapability = {
			toolClass: "http",
			actions: ["get"],
			constraints: {
				allowedHosts: ["api.example.com", "cdn.example.com"],
			},
		};
		const request: Capability = {
			toolClass: "http",
			actions: ["get"],
			constraints: {
				allowedHosts: ["api.example.com", "evil.com"],
			},
		};

		const result = delegateCapability(parent, request, parentId, childId);

		expect(result.granted).toBe(true);
		expect(result.capability?.constraints?.allowedHosts).toEqual(["api.example.com"]);
	});

	it("denies when tool class does not match", () => {
		const parent: DelegatedCapability = { toolClass: "http", actions: ["get"] };
		const request: Capability = { toolClass: "shell", actions: ["exec"] };

		const result = delegateCapability(parent, request, parentId, childId);

		expect(result.granted).toBe(false);
		expect(result.reason).toContain("Tool class mismatch");
	});

	it("denies when no actions overlap", () => {
		const parent: DelegatedCapability = { toolClass: "http", actions: ["get"] };
		const request: Capability = { toolClass: "http", actions: ["post", "delete"] };

		const result = delegateCapability(parent, request, parentId, childId);

		expect(result.granted).toBe(false);
		expect(result.reason).toContain("No overlapping actions");
	});

	it("prevents widening — child cannot gain actions parent lacks", () => {
		const parent: DelegatedCapability = {
			toolClass: "file",
			actions: ["read"],
			constraints: { allowedPaths: ["/data"] },
		};
		const request: Capability = {
			toolClass: "file",
			actions: ["read", "write"],
			constraints: { allowedPaths: ["/data", "/etc"] },
		};

		const result = delegateCapability(parent, request, parentId, childId);

		expect(result.granted).toBe(true);
		expect(result.capability?.actions).toEqual(["read"]);
		expect(result.capability?.constraints?.allowedPaths).toEqual(["/data"]);
	});

	it("uses the stricter maxCallsPerMinute", () => {
		const parent: DelegatedCapability = {
			toolClass: "http",
			constraints: { maxCallsPerMinute: 100 },
		};
		const request: Capability = {
			toolClass: "http",
			constraints: { maxCallsPerMinute: 50 },
		};

		const result = delegateCapability(parent, request, parentId, childId);

		expect(result.granted).toBe(true);
		expect(result.capability?.constraints?.maxCallsPerMinute).toBe(50);
	});

	it("parent maxCallsPerMinute wins when stricter", () => {
		const parent: DelegatedCapability = {
			toolClass: "http",
			constraints: { maxCallsPerMinute: 10 },
		};
		const request: Capability = {
			toolClass: "http",
			constraints: { maxCallsPerMinute: 50 },
		};

		const result = delegateCapability(parent, request, parentId, childId);

		expect(result.granted).toBe(true);
		expect(result.capability?.constraints?.maxCallsPerMinute).toBe(10);
	});

	it("records delegation metadata", () => {
		const parent: DelegatedCapability = { toolClass: "http", actions: ["get"] };
		const request: Capability = { toolClass: "http", actions: ["get"] };

		const result = delegateCapability(parent, request, parentId, childId, "2026-01-01T00:00:00Z");

		expect(result.capability?.delegation).toEqual({
			issuedBy: parentId,
			delegatedTo: childId,
			delegationChain: [parentId, childId],
			delegatedAt: "2026-01-01T00:00:00Z",
		});
	});

	it("extends existing delegation chain for multi-hop", () => {
		const grandparentId = "grandparent-001";
		const parentCap: DelegatedCapability = {
			toolClass: "http",
			actions: ["get", "head"],
			delegation: {
				issuedBy: grandparentId,
				delegatedTo: parentId,
				delegationChain: [grandparentId, parentId],
				delegatedAt: "2026-01-01T00:00:00Z",
			},
		};
		const request: Capability = { toolClass: "http", actions: ["get"] };

		const result = delegateCapability(parentCap, request, parentId, childId);

		expect(result.granted).toBe(true);
		expect(result.capability?.delegation?.delegationChain).toEqual([
			grandparentId,
			parentId,
			childId,
		]);
		expect(result.capability?.actions).toEqual(["get"]);
	});

	it("passes through unconstrained parent when child requests subset", () => {
		const parent: DelegatedCapability = { toolClass: "http" }; // no actions/constraints
		const request: Capability = { toolClass: "http", actions: ["get"] };

		const result = delegateCapability(parent, request, parentId, childId);

		expect(result.granted).toBe(true);
		expect(result.capability?.actions).toEqual(["get"]);
	});
});

describe("createDelegatedPrincipal", () => {
	const parent: Principal & { capabilities: DelegatedCapability[] } = {
		id: "parent-001",
		name: "Planner Agent",
		capabilities: [
			{ toolClass: "http", actions: ["get", "post"] },
			{ toolClass: "file", actions: ["read"], constraints: { allowedPaths: ["/data"] } },
		],
	};

	it("creates a child principal with narrowed capabilities", () => {
		const { principal: child, denied } = createDelegatedPrincipal(
			parent,
			"child-001",
			"Scraper Agent",
			[
				{ toolClass: "http", actions: ["get"] },
				{ toolClass: "file", actions: ["read"] },
			],
		);

		expect(denied).toHaveLength(0);
		expect(child.id).toBe("child-001");
		expect(child.name).toBe("Scraper Agent");
		expect(child.parentId).toBe("parent-001");
		expect(child.capabilities).toHaveLength(2);
		expect(child.capabilities[0].actions).toEqual(["get"]);
		expect(child.capabilities[1].constraints?.allowedPaths).toEqual(["/data"]);
	});

	it("denies capabilities the parent does not hold", () => {
		const { principal: child, denied } = createDelegatedPrincipal(
			parent,
			"child-001",
			"Shell Agent",
			[{ toolClass: "shell", actions: ["exec"] }],
		);

		expect(child.capabilities).toHaveLength(0);
		expect(denied).toHaveLength(1);
		expect(denied[0].reason).toContain("no capability for 'shell'");
	});
});

describe("validateDelegationChain", () => {
	it("validates a correct chain", () => {
		const caps: DelegatedCapability[] = [
			{
				toolClass: "http",
				delegation: {
					issuedBy: "A",
					delegatedTo: "B",
					delegationChain: ["A", "B"],
					delegatedAt: "2026-01-01T00:00:00Z",
				},
			},
		];
		expect(validateDelegationChain(caps)).toBe(true);
	});

	it("rejects a chain where delegatedTo does not match last entry", () => {
		const caps: DelegatedCapability[] = [
			{
				toolClass: "http",
				delegation: {
					issuedBy: "A",
					delegatedTo: "C",
					delegationChain: ["A", "B"],
					delegatedAt: "2026-01-01T00:00:00Z",
				},
			},
		];
		expect(validateDelegationChain(caps)).toBe(false);
	});

	it("accepts capabilities without delegation metadata", () => {
		const caps: DelegatedCapability[] = [{ toolClass: "http" }];
		expect(validateDelegationChain(caps)).toBe(true);
	});
});

describe("revokeDelegationsFrom", () => {
	it("removes capabilities delegated through a revoked principal", () => {
		const caps: DelegatedCapability[] = [
			{
				toolClass: "http",
				delegation: {
					issuedBy: "A",
					delegatedTo: "B",
					delegationChain: ["A", "B"],
					delegatedAt: "2026-01-01T00:00:00Z",
				},
			},
			{
				toolClass: "file",
				delegation: {
					issuedBy: "B",
					delegatedTo: "C",
					delegationChain: ["A", "B", "C"],
					delegatedAt: "2026-01-01T00:00:00Z",
				},
			},
			{ toolClass: "database" }, // no delegation — should be preserved
		];

		// Revoking B removes B's direct capability AND C's transitive one
		const remaining = revokeDelegationsFrom(caps, "B");
		expect(remaining).toHaveLength(1);
		expect(remaining[0].toolClass).toBe("database");
	});

	it("preserves capabilities not in the revoked chain", () => {
		const caps: DelegatedCapability[] = [
			{
				toolClass: "http",
				delegation: {
					issuedBy: "X",
					delegatedTo: "Y",
					delegationChain: ["X", "Y"],
					delegatedAt: "2026-01-01T00:00:00Z",
				},
			},
		];

		const remaining = revokeDelegationsFrom(caps, "Z");
		expect(remaining).toHaveLength(1);
	});
});
