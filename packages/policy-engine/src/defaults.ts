import type { PolicyRule } from "@arikernel/core";

export const DENY_ALL_RULE: PolicyRule = {
	id: "__builtin_deny_all",
	name: "Deny All (default)",
	priority: 999,
	match: {},
	decision: "deny",
	reason: "No matching policy (deny-by-default)",
	tags: ["builtin"],
};

export const DEFAULT_RULES: PolicyRule[] = [DENY_ALL_RULE];
