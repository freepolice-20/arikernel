/**
 * Canonical action taxonomy for AriKernel tool classes.
 *
 * Every valid (toolClass, action) pair is registered here.
 * Security-critical code must use these constants and helpers
 * instead of ad-hoc string sets — so a new executor action
 * that isn't registered here fails closed rather than silently
 * bypassing policy checks.
 */

import type { ToolClass } from "./principal.js";

// ── Per-tool-class action constants ────────────────────────────────

export const HTTP_ACTIONS = ["get", "head", "options", "post", "put", "patch", "delete"] as const;
export const FILE_ACTIONS = ["read", "write"] as const;
export const SHELL_ACTIONS = ["exec"] as const;
export const DATABASE_ACTIONS = ["query", "exec", "mutate"] as const;
export const BROWSER_ACTIONS = ["navigate", "click", "fill", "submit"] as const;
export const RETRIEVAL_ACTIONS = ["search", "retrieve"] as const;

export type HttpAction = (typeof HTTP_ACTIONS)[number];
export type FileAction = (typeof FILE_ACTIONS)[number];
export type ShellAction = (typeof SHELL_ACTIONS)[number];
export type DatabaseAction = (typeof DATABASE_ACTIONS)[number];
export type BrowserAction = (typeof BROWSER_ACTIONS)[number];
export type RetrievalAction = (typeof RETRIEVAL_ACTIONS)[number];

/**
 * Complete registry of known actions per tool class.
 * MCP actions are dynamic (tool name = action) so they are not listed.
 */
export const TOOL_CLASS_ACTIONS: Record<string, readonly string[]> = {
	http: HTTP_ACTIONS,
	file: FILE_ACTIONS,
	shell: SHELL_ACTIONS,
	database: DATABASE_ACTIONS,
	browser: BROWSER_ACTIONS,
	retrieval: RETRIEVAL_ACTIONS,
};

// ── Action categories ──────────────────────────────────────────────

/**
 * Coarse-grained action categories for security decisions.
 * Executors map their specific actions into one of these.
 */
export const ACTION_CATEGORIES = ["read", "write", "execute"] as const;
export type ActionCategory = (typeof ACTION_CATEGORIES)[number];

/**
 * Mapping from (toolClass, action) → ActionCategory.
 * Built from a compact declaration, not scattered string sets.
 */
const CATEGORY_MAP: ReadonlyMap<string, ActionCategory> = buildCategoryMap({
	read: {
		http: ["get", "head", "options"],
		file: ["read"],
		database: ["query"],
		browser: ["navigate"],
		retrieval: ["search", "retrieve"],
	},
	write: {
		http: ["post", "put", "patch", "delete"],
		file: ["write"],
		database: ["mutate"],
		browser: ["click", "fill", "submit"],
	},
	execute: {
		shell: ["exec"],
		database: ["exec"],
	},
});

function buildCategoryMap(
	spec: Record<ActionCategory, Record<string, string[]>>,
): Map<string, ActionCategory> {
	const map = new Map<string, ActionCategory>();
	for (const [category, toolClasses] of Object.entries(spec)) {
		for (const [toolClass, actions] of Object.entries(toolClasses)) {
			for (const action of actions) {
				map.set(`${toolClass}:${action}`, category as ActionCategory);
			}
		}
	}
	return map;
}

/**
 * Categorize a (toolClass, action) pair.
 *
 * Returns the canonical ActionCategory, or "write" for unknown actions
 * (fail-closed: unknown actions are treated as writes).
 */
export function categorizeAction(toolClass: string, action: string): ActionCategory {
	return CATEGORY_MAP.get(`${toolClass}:${action.toLowerCase()}`) ?? "write";
}

/**
 * Check whether an action is known for the given tool class.
 * MCP actions are always considered known (dynamic tool names).
 *
 * Returns false for unregistered actions — callers should log a
 * warning and treat the action as a write.
 */
export function isKnownAction(toolClass: ToolClass, action: string): boolean {
	if (toolClass === "mcp") return true;
	const known = TOOL_CLASS_ACTIONS[toolClass];
	if (!known) return false;
	return known.includes(action.toLowerCase());
}

/**
 * Check whether an action is a write-or-execute (i.e. NOT read-only).
 * Unknown actions return true (fail-closed).
 */
export function isWriteAction(toolClass: string, action: string): boolean {
	return categorizeAction(toolClass, action) !== "read";
}
