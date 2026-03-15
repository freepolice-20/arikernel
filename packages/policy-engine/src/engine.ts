import { resolve } from "node:path";
import type { Capability, Decision, PolicyRule, TaintLabel, ToolCall } from "@arikernel/core";
import { isKnownAction, now } from "@arikernel/core";
import { DEFAULT_RULES } from "./defaults.js";
import { loadPolicies } from "./loader.js";
import { UnsafeMatchError, matchesRule } from "./matcher.js";

export class PolicyEngine {
	private rules: PolicyRule[] = [];

	constructor(policies?: string | PolicyRule[]) {
		this.rules = [...DEFAULT_RULES];
		if (policies) {
			const loaded = loadPolicies(policies);
			this.rules = [...this.rules, ...loaded];
		}
		this.rules.sort((a, b) => a.priority - b.priority);
	}

	evaluate(toolCall: ToolCall, taintLabels: TaintLabel[], capabilities: Capability[]): Decision {
		const timestamp = now();

		// Step 1: capability check
		const capability = capabilities.find((c) => c.toolClass === toolCall.toolClass);
		if (!capability) {
			return {
				verdict: "deny",
				matchedRule: null,
				reason: `No capability grant for tool class: ${toolCall.toolClass}`,
				taintLabels,
				timestamp,
			};
		}

		// Step 2: action check within capability (case-insensitive)
		if (capability.actions && capability.actions.length > 0) {
			const normalizedAction = toolCall.action.toLowerCase();
			const permitted = capability.actions.map((a) => a.toLowerCase());
			if (!permitted.includes(normalizedAction)) {
				return {
					verdict: "deny",
					matchedRule: null,
					reason: `Action '${toolCall.action}' not allowed. Permitted: ${capability.actions.join(", ")}`,
					taintLabels,
					timestamp,
				};
			}
		}

		// Step 2b: warn on unknown actions (fail-closed via categorizeAction downstream)
		if (!isKnownAction(toolCall.toolClass, toolCall.action)) {
			console.warn(
				`[arikernel] Unknown action '${toolCall.action}' for tool class '${toolCall.toolClass}' — treating as write`,
			);
		}

		// Step 3: constraint check
		const constraintViolation = checkConstraints(toolCall, capability);
		if (constraintViolation) {
			return {
				verdict: "deny",
				matchedRule: null,
				reason: constraintViolation,
				taintLabels,
				timestamp,
			};
		}

		// Step 4: policy rules (sorted by priority, first match wins)
		for (const rule of this.rules) {
			try {
				if (matchesRule(rule.match, toolCall, taintLabels)) {
					return {
						verdict: rule.decision,
						matchedRule: rule,
						reason: rule.reason,
						taintLabels,
						timestamp,
					};
				}
			} catch (err) {
				// UnsafeMatchError: regex evaluation was unsafe (invalid pattern,
				// oversized input, etc.). Fail closed — deny unconditionally.
				// This ensures a slow/broken regex on a deny rule cannot silently
				// convert into an allow by being treated as "non-match."
				if (err instanceof UnsafeMatchError) {
					return {
						verdict: "deny",
						matchedRule: rule,
						reason: `Policy rule '${rule.id}' triggered unsafe match: ${err.message}`,
						taintLabels,
						timestamp,
					};
				}
				throw err;
			}
		}

		// Step 5: implicit deny (should not reach here since DENY_ALL is in rules)
		return {
			verdict: "deny",
			matchedRule: null,
			reason: "No matching policy (deny-by-default)",
			taintLabels,
			timestamp,
		};
	}

	getRules(): readonly PolicyRule[] {
		return this.rules;
	}
}

function checkConstraints(toolCall: ToolCall, capability: Capability): string | null {
	const constraints = capability.constraints;
	if (!constraints) return null;

	if (constraints.allowedHosts && toolCall.toolClass === "http") {
		const url = String(toolCall.parameters.url ?? "");
		try {
			const hostname = new URL(url).hostname;
			if (!constraints.allowedHosts.includes("*") && !constraints.allowedHosts.includes(hostname)) {
				return `Host '${hostname}' not in allowed hosts: ${constraints.allowedHosts.join(", ")}`;
			}
		} catch {
			return `Invalid URL: ${url}`;
		}
	}

	if (constraints.allowedCommands && toolCall.toolClass === "shell") {
		const command = String(toolCall.parameters.command ?? "");
		const binary = command.split(/\s+/)[0];
		if (!constraints.allowedCommands.includes(binary)) {
			return `Command '${binary}' not in allowed commands: ${constraints.allowedCommands.join(", ")}`;
		}
	}

	if (constraints.allowedPaths && toolCall.toolClass === "file") {
		const rawPath = String(toolCall.parameters.path ?? "");
		// Canonicalize via resolve() to strip ../ traversal sequences before comparing.
		// Note: resolve() normalizes but does not follow symlinks; the execution-time
		// pipeline.ts check uses isPathAllowed() (with realpathSync) as the final gate.
		const canonicalPath = resolve(rawPath);
		const sep = process.platform === "win32" ? "\\" : "/";
		const allowed = constraints.allowedPaths.some((pattern) => {
			if (pattern.endsWith("/**")) {
				const base = resolve(pattern.slice(0, -3));
				return canonicalPath === base || canonicalPath.startsWith(base + sep);
			}
			return canonicalPath === resolve(pattern);
		});
		if (!allowed) {
			return `Path '${canonicalPath}' not in allowed paths: ${constraints.allowedPaths.join(", ")}`;
		}
	}

	return null;
}
