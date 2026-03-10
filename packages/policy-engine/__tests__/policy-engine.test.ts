import type { Capability, PolicyRule, TaintLabel, ToolCall } from "@arikernel/core";
import { describe, expect, it } from "vitest";
import { DEFAULT_RULES, DENY_ALL_RULE, PolicyEngine, UnsafeMatchError, matchesRule } from "../src/index.js";

function makeToolCall(overrides: Partial<ToolCall> = {}): ToolCall {
	return {
		id: "tc-1",
		runId: "run-1",
		sequence: 0,
		timestamp: new Date().toISOString(),
		principalId: "agent",
		toolClass: "http",
		action: "get",
		parameters: {},
		taintLabels: [],
		...overrides,
	};
}

function makeCapability(overrides: Partial<Capability> = {}): Capability {
	return {
		toolClass: "http",
		actions: ["get", "post"],
		...overrides,
	};
}

function makeTaintLabel(overrides: Partial<TaintLabel> = {}): TaintLabel {
	return {
		source: "web",
		origin: "example.com",
		confidence: 1.0,
		addedAt: new Date().toISOString(),
		...overrides,
	};
}

describe("PolicyEngine", () => {
	it("denies when no capability grant exists", () => {
		const engine = new PolicyEngine();
		const tc = makeToolCall({ toolClass: "shell", action: "exec" });
		const decision = engine.evaluate(tc, [], [makeCapability({ toolClass: "http" })]);
		expect(decision.verdict).toBe("deny");
		expect(decision.reason).toContain("No capability grant");
	});

	it("denies when action is not in capability.actions", () => {
		const engine = new PolicyEngine();
		const tc = makeToolCall({ action: "delete" });
		const decision = engine.evaluate(tc, [], [makeCapability({ actions: ["get", "post"] })]);
		expect(decision.verdict).toBe("deny");
		expect(decision.reason).toContain("Action 'delete' not allowed");
	});

	it("allows when capability.actions is empty (no action restriction)", () => {
		const allowRule: PolicyRule = {
			id: "allow-http",
			name: "Allow HTTP",
			priority: 1,
			match: { toolClass: "http" },
			decision: "allow",
			reason: "Allowed",
		};
		const engine = new PolicyEngine([allowRule]);
		const tc = makeToolCall({ action: "patch" });
		const decision = engine.evaluate(tc, [], [makeCapability({ actions: [] })]);
		expect(decision.verdict).toBe("allow");
	});

	it("sorts rules by priority (lowest number wins)", () => {
		const lowPriority: PolicyRule = {
			id: "low",
			name: "Low Priority Allow",
			priority: 100,
			match: { toolClass: "http" },
			decision: "allow",
			reason: "Low priority",
		};
		const highPriority: PolicyRule = {
			id: "high",
			name: "High Priority Deny",
			priority: 1,
			match: { toolClass: "http" },
			decision: "deny",
			reason: "High priority",
		};
		const engine = new PolicyEngine([lowPriority, highPriority]);
		const tc = makeToolCall();
		const decision = engine.evaluate(tc, [], [makeCapability()]);
		expect(decision.verdict).toBe("deny");
		expect(decision.matchedRule?.id).toBe("high");
	});

	it("falls back to DENY_ALL_RULE when no custom rules match", () => {
		const engine = new PolicyEngine();
		const tc = makeToolCall();
		const decision = engine.evaluate(tc, [], [makeCapability()]);
		expect(decision.verdict).toBe("deny");
		expect(decision.matchedRule?.id).toBe("__builtin_deny_all");
	});

	it("getRules returns all rules including defaults", () => {
		const customRule: PolicyRule = {
			id: "custom",
			name: "Custom",
			priority: 50,
			match: {},
			decision: "allow",
			reason: "Custom rule",
		};
		const engine = new PolicyEngine([customRule]);
		const rules = engine.getRules();
		expect(rules.length).toBe(DEFAULT_RULES.length + 1);
		expect(rules.some((r) => r.id === "custom")).toBe(true);
		expect(rules.some((r) => r.id === "__builtin_deny_all")).toBe(true);
	});

	it("returns require-approval verdict when rule specifies it", () => {
		const approvalRule: PolicyRule = {
			id: "needs-approval",
			name: "Needs Approval",
			priority: 1,
			match: { toolClass: "shell" },
			decision: "require-approval",
			reason: "Shell requires approval",
		};
		const engine = new PolicyEngine([approvalRule]);
		const tc = makeToolCall({ toolClass: "shell", action: "exec" });
		const decision = engine.evaluate(
			tc,
			[],
			[makeCapability({ toolClass: "shell", actions: ["exec"] })],
		);
		expect(decision.verdict).toBe("require-approval");
	});
});

describe("Constraint checking", () => {
	it("blocks HTTP to disallowed host", () => {
		const engine = new PolicyEngine();
		const tc = makeToolCall({ parameters: { url: "https://evil.com/data" } });
		const cap = makeCapability({ constraints: { allowedHosts: ["example.com"] } });
		const decision = engine.evaluate(tc, [], [cap]);
		expect(decision.verdict).toBe("deny");
		expect(decision.reason).toContain("Host 'evil.com' not in allowed hosts");
	});

	it("allows HTTP when host matches allowedHosts", () => {
		const allowRule: PolicyRule = {
			id: "allow-http",
			name: "Allow HTTP",
			priority: 1,
			match: { toolClass: "http" },
			decision: "allow",
			reason: "Allowed",
		};
		const engine = new PolicyEngine([allowRule]);
		const tc = makeToolCall({ parameters: { url: "https://example.com/api" } });
		const cap = makeCapability({ constraints: { allowedHosts: ["example.com"] } });
		const decision = engine.evaluate(tc, [], [cap]);
		expect(decision.verdict).toBe("allow");
	});

	it("allows HTTP when allowedHosts contains wildcard *", () => {
		const allowRule: PolicyRule = {
			id: "allow-http",
			name: "Allow HTTP",
			priority: 1,
			match: { toolClass: "http" },
			decision: "allow",
			reason: "Allowed",
		};
		const engine = new PolicyEngine([allowRule]);
		const tc = makeToolCall({ parameters: { url: "https://anything.com/path" } });
		const cap = makeCapability({ constraints: { allowedHosts: ["*"] } });
		const decision = engine.evaluate(tc, [], [cap]);
		expect(decision.verdict).toBe("allow");
	});

	it("denies HTTP with invalid URL", () => {
		const engine = new PolicyEngine();
		const tc = makeToolCall({ parameters: { url: "not-a-url" } });
		const cap = makeCapability({ constraints: { allowedHosts: ["example.com"] } });
		const decision = engine.evaluate(tc, [], [cap]);
		expect(decision.verdict).toBe("deny");
		expect(decision.reason).toContain("Invalid URL");
	});

	it("blocks shell command not in allowedCommands", () => {
		const engine = new PolicyEngine();
		const tc = makeToolCall({
			toolClass: "shell",
			action: "exec",
			parameters: { command: "rm -rf /" },
		});
		const cap = makeCapability({
			toolClass: "shell",
			actions: ["exec"],
			constraints: { allowedCommands: ["ls", "cat"] },
		});
		const decision = engine.evaluate(tc, [], [cap]);
		expect(decision.verdict).toBe("deny");
		expect(decision.reason).toContain("Command 'rm' not in allowed commands");
	});

	it("allows shell command in allowedCommands", () => {
		const allowRule: PolicyRule = {
			id: "allow-shell",
			name: "Allow shell",
			priority: 1,
			match: { toolClass: "shell" },
			decision: "allow",
			reason: "Allowed",
		};
		const engine = new PolicyEngine([allowRule]);
		const tc = makeToolCall({
			toolClass: "shell",
			action: "exec",
			parameters: { command: "ls -la /tmp" },
		});
		const cap = makeCapability({
			toolClass: "shell",
			actions: ["exec"],
			constraints: { allowedCommands: ["ls", "cat"] },
		});
		const decision = engine.evaluate(tc, [], [cap]);
		expect(decision.verdict).toBe("allow");
	});

	it("blocks file path not in allowedPaths", () => {
		const engine = new PolicyEngine();
		const tc = makeToolCall({
			toolClass: "file",
			action: "read",
			parameters: { path: "/etc/shadow" },
		});
		const cap = makeCapability({
			toolClass: "file",
			actions: ["read", "write"],
			constraints: { allowedPaths: ["/home/user/**"] },
		});
		const decision = engine.evaluate(tc, [], [cap]);
		expect(decision.verdict).toBe("deny");
		expect(decision.reason).toContain("Path '/etc/shadow' not in allowed paths");
	});

	it("allows file path matching /** wildcard", () => {
		const allowRule: PolicyRule = {
			id: "allow-file",
			name: "Allow file",
			priority: 1,
			match: { toolClass: "file" },
			decision: "allow",
			reason: "Allowed",
		};
		const engine = new PolicyEngine([allowRule]);
		const tc = makeToolCall({
			toolClass: "file",
			action: "read",
			parameters: { path: "/home/user/docs/file.txt" },
		});
		const cap = makeCapability({
			toolClass: "file",
			actions: ["read", "write"],
			constraints: { allowedPaths: ["/home/user/**"] },
		});
		const decision = engine.evaluate(tc, [], [cap]);
		expect(decision.verdict).toBe("allow");
	});

	it("allows file path with exact match", () => {
		const allowRule: PolicyRule = {
			id: "allow-file",
			name: "Allow file",
			priority: 1,
			match: { toolClass: "file" },
			decision: "allow",
			reason: "Allowed",
		};
		const engine = new PolicyEngine([allowRule]);
		const tc = makeToolCall({
			toolClass: "file",
			action: "read",
			parameters: { path: "/specific/file.txt" },
		});
		const cap = makeCapability({
			toolClass: "file",
			actions: ["read"],
			constraints: { allowedPaths: ["/specific/file.txt"] },
		});
		const decision = engine.evaluate(tc, [], [cap]);
		expect(decision.verdict).toBe("allow");
	});
});

describe("matchesRule", () => {
	it("matches when all fields are undefined (catch-all)", () => {
		const tc = makeToolCall();
		expect(matchesRule({}, tc, [])).toBe(true);
	});

	it("matches toolClass as string", () => {
		const tc = makeToolCall({ toolClass: "http" });
		expect(matchesRule({ toolClass: "http" }, tc, [])).toBe(true);
		expect(matchesRule({ toolClass: "shell" }, tc, [])).toBe(false);
	});

	it("matches toolClass as array", () => {
		const tc = makeToolCall({ toolClass: "file" });
		expect(matchesRule({ toolClass: ["http", "file"] }, tc, [])).toBe(true);
		expect(matchesRule({ toolClass: ["http", "shell"] }, tc, [])).toBe(false);
	});

	it("matches action as string", () => {
		const tc = makeToolCall({ action: "get" });
		expect(matchesRule({ action: "get" }, tc, [])).toBe(true);
		expect(matchesRule({ action: "post" }, tc, [])).toBe(false);
	});

	it("matches action as array", () => {
		const tc = makeToolCall({ action: "get" });
		expect(matchesRule({ action: ["get", "head"] }, tc, [])).toBe(true);
		expect(matchesRule({ action: ["post", "put"] }, tc, [])).toBe(false);
	});

	it("matches principalId", () => {
		const tc = makeToolCall({ principalId: "agent-a" });
		expect(matchesRule({ principalId: "agent-a" }, tc, [])).toBe(true);
		expect(matchesRule({ principalId: "agent-b" }, tc, [])).toBe(false);
	});

	it("matches taint sources (OR logic)", () => {
		const labels = [makeTaintLabel({ source: "web" })];
		const tc = makeToolCall();
		expect(matchesRule({ taintSources: ["web"] }, tc, labels)).toBe(true);
		expect(matchesRule({ taintSources: ["email"] }, tc, labels)).toBe(false);
		expect(matchesRule({ taintSources: ["email", "web"] }, tc, labels)).toBe(true);
	});

	it("matches empty taintSources as wildcard", () => {
		const tc = makeToolCall();
		expect(matchesRule({ taintSources: [] }, tc, [])).toBe(true);
	});

	it("matches parameter pattern", () => {
		const tc = makeToolCall({ parameters: { url: "https://evil.com/steal" } });
		expect(matchesRule({ parameters: { url: { pattern: "evil\\.com" } } }, tc, [])).toBe(true);
		expect(matchesRule({ parameters: { url: { pattern: "good\\.com" } } }, tc, [])).toBe(false);
	});

	it("matches parameter in/notIn", () => {
		const tc = makeToolCall({ parameters: { method: "DELETE" } });
		expect(matchesRule({ parameters: { method: { in: ["GET", "DELETE"] } } }, tc, [])).toBe(true);
		expect(matchesRule({ parameters: { method: { in: ["GET", "POST"] } } }, tc, [])).toBe(false);
		expect(matchesRule({ parameters: { method: { notIn: ["DELETE"] } } }, tc, [])).toBe(false);
		expect(matchesRule({ parameters: { method: { notIn: ["GET"] } } }, tc, [])).toBe(true);
	});

	it("coerces missing parameter to empty string", () => {
		const tc = makeToolCall({ parameters: {} });
		expect(matchesRule({ parameters: { missing: { in: [""] } } }, tc, [])).toBe(true);
		expect(matchesRule({ parameters: { missing: { in: ["something"] } } }, tc, [])).toBe(false);
	});
});

describe("fail-closed regex matching", () => {
	it("throws UnsafeMatchError on invalid regex pattern", () => {
		const tc = makeToolCall({ parameters: { url: "https://example.com" } });
		expect(() =>
			matchesRule({ parameters: { url: { pattern: "[invalid" } } }, tc, []),
		).toThrow(UnsafeMatchError);
	});

	it("throws UnsafeMatchError on oversized input", () => {
		const oversized = "a".repeat(10000);
		const tc = makeToolCall({ parameters: { url: oversized } });
		expect(() =>
			matchesRule({ parameters: { url: { pattern: "a+" } } }, tc, []),
		).toThrow(UnsafeMatchError);
	});

	it("engine denies on invalid regex in deny rule (fail-closed)", () => {
		const denyRule: PolicyRule = {
			id: "deny-evil",
			name: "Deny evil URLs",
			priority: 1,
			match: { toolClass: "http", parameters: { url: { pattern: "[invalid" } } },
			decision: "deny",
			reason: "Evil URL blocked",
		};
		const engine = new PolicyEngine([denyRule]);
		const tc = makeToolCall({ parameters: { url: "https://example.com" } });
		const decision = engine.evaluate(tc, [], [makeCapability()]);
		expect(decision.verdict).toBe("deny");
		expect(decision.reason).toContain("unsafe match");
	});

	it("engine denies on invalid regex in allow rule (fail-closed)", () => {
		// Even if the broken rule is an allow rule, UnsafeMatchError → deny
		const allowRule: PolicyRule = {
			id: "allow-good",
			name: "Allow good URLs",
			priority: 1,
			match: { toolClass: "http", parameters: { url: { pattern: "[invalid" } } },
			decision: "allow",
			reason: "Good URL allowed",
		};
		const engine = new PolicyEngine([allowRule]);
		const tc = makeToolCall({ parameters: { url: "https://example.com" } });
		const decision = engine.evaluate(tc, [], [makeCapability()]);
		expect(decision.verdict).toBe("deny");
	});

	it("engine denies on oversized input targeting deny rule", () => {
		const denyRule: PolicyRule = {
			id: "deny-pattern",
			name: "Deny pattern",
			priority: 1,
			match: { toolClass: "http", parameters: { url: { pattern: "evil" } } },
			decision: "deny",
			reason: "Denied",
		};
		const engine = new PolicyEngine([denyRule]);
		const oversized = "a".repeat(10000);
		const tc = makeToolCall({ parameters: { url: oversized } });
		const decision = engine.evaluate(tc, [], [makeCapability()]);
		expect(decision.verdict).toBe("deny");
		expect(decision.reason).toContain("exceeds maximum safe length");
	});

	it("normal regex matching still works for valid patterns and inputs", () => {
		const tc = makeToolCall({ parameters: { url: "https://evil.com/steal" } });
		expect(matchesRule({ parameters: { url: { pattern: "evil\\.com" } } }, tc, [])).toBe(true);
		expect(matchesRule({ parameters: { url: { pattern: "good\\.com" } } }, tc, [])).toBe(false);
	});
});

describe("DENY_ALL_RULE", () => {
	it("has priority 999", () => {
		expect(DENY_ALL_RULE.priority).toBe(999);
	});

	it("matches any tool call", () => {
		const tc = makeToolCall({ toolClass: "shell", action: "exec", principalId: "anyone" });
		expect(matchesRule(DENY_ALL_RULE.match, tc, [])).toBe(true);
	});

	it("verdict is deny", () => {
		expect(DENY_ALL_RULE.decision).toBe("deny");
	});
});
