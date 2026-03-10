/**
 * Shared middleware utilities — kernel factory and tool mapping inference.
 *
 * All framework-specific middleware wrappers use these primitives internally.
 */

import { type PresetId, type TaintLabel, getPreset } from '@arikernel/core';
import type { Firewall, KernelAllow, FirewallHooks, Kernel } from '@arikernel/runtime';
import { createKernel } from '@arikernel/runtime';

export interface MiddlewareOptions {
	/** Security preset. Default: zero-config safe defaults. */
	preset?: PresetId;
	/** Explicit capability overrides (alternative to preset). */
	allow?: KernelAllow;
	/** Principal name for audit attribution. Default: 'agent'. */
	principal?: string;
	/** Audit log path. Default: ':memory:'. */
	auditLog?: string;
	/** Firewall lifecycle hooks. */
	hooks?: FirewallHooks;
	/** Tool name → Ari Kernel tool class mapping. Auto-inferred if omitted. */
	toolMappings?: Record<string, ToolMapping>;
	/** Derive taint labels from tool parameters in stub executors. Default: false. */
	autoTaint?: boolean;
}

export interface ToolMapping {
	toolClass: string;
	action: string;
}

/**
 * Create a firewall from middleware options.
 *
 * Handles kernel creation, preset resolution, and firewall instantiation
 * so each middleware wrapper doesn't duplicate this logic.
 */
export function createMiddlewareFirewall(options: MiddlewareOptions = {}): Firewall {
	// Resolve runStatePolicy: preset-specific → default fallback
	const presetId = options.allow ? undefined : options.preset;
	const presetRunState = presetId ? getPreset(presetId).runStatePolicy : undefined;
	const runStatePolicy = presetRunState ?? { maxDeniedSensitiveActions: 10, behavioralRules: true };

	const kernel = createKernel({
		preset: presetId,
		allow: options.allow,
		principal: options.principal,
		auditLog: options.auditLog ?? ':memory:',
		hooks: options.hooks,
		runStatePolicy,
	});
	return kernel.createFirewall();
}

/** Name patterns → tool class/action mapping. */
const TOOL_PATTERNS: Array<{ pattern: RegExp; toolClass: string; action: string }> = [
	// HTTP read
	{ pattern: /^(web_search|web_fetch|http_get|fetch_url|browse|scrape|search_web)$/i, toolClass: 'http', action: 'get' },
	// HTTP write
	{ pattern: /^(http_post|send_request|post_data|web_post)$/i, toolClass: 'http', action: 'post' },
	// File read
	{ pattern: /^(read_file|file_read|load_file|get_file|read_document)$/i, toolClass: 'file', action: 'read' },
	// File write
	{ pattern: /^(write_file|file_write|save_file|create_file)$/i, toolClass: 'file', action: 'write' },
	// Shell
	{ pattern: /^(run_shell|shell_exec|exec_command|run_command|terminal|bash|execute)$/i, toolClass: 'shell', action: 'exec' },
	// Database read
	{ pattern: /^(query_db|sql_query|db_query|database_read|db_read|run_query)$/i, toolClass: 'database', action: 'query' },
	// Database write
	{ pattern: /^(db_write|sql_insert|db_insert|database_write|db_update)$/i, toolClass: 'database', action: 'write' },
	// Email (maps to http.post — egress)
	{ pattern: /^(send_email|email_send|send_message)$/i, toolClass: 'http', action: 'post' },
];

/**
 * Best-effort inference of tool class and action from a tool name.
 *
 * Returns null if no pattern matches — the tool will be passed through
 * unprotected unless an explicit mapping is provided.
 */
export function inferToolMapping(toolName: string): ToolMapping | null {
	for (const { pattern, toolClass, action } of TOOL_PATTERNS) {
		if (pattern.test(toolName)) {
			return { toolClass, action };
		}
	}
	return null;
}

/**
 * Resolve tool mappings for a list of tool names.
 *
 * Explicit mappings take priority. Remaining tools are auto-inferred
 * from naming patterns. Tools that can't be mapped are omitted.
 */
export function resolveToolMappings(
	toolNames: string[],
	explicit?: Record<string, ToolMapping>,
): Record<string, ToolMapping> {
	const result: Record<string, ToolMapping> = {};
	for (const name of toolNames) {
		if (explicit?.[name]) {
			result[name] = explicit[name];
			continue;
		}
		const inferred = inferToolMapping(name);
		if (inferred) {
			result[name] = inferred;
		}
	}
	return result;
}

/**
 * Register stub executors for all unique tool classes in a mapping set.
 *
 * The firewall pipeline requires a registered executor for each tool class.
 * These stubs pass through security checks (capability, policy, taint,
 * behavioral rules, audit) without performing real I/O.
 *
 * When `autoTaint` is true, stub executors derive taint labels from the tool
 * call parameters (e.g. hostname from `url` for HTTP tools).
 */
export function registerStubExecutors(
	firewall: Firewall,
	mappings: Record<string, ToolMapping>,
	autoTaint = false,
): void {
	const toolClasses = new Set(Object.values(mappings).map((m) => m.toolClass));
	for (const tc of toolClasses) {
		firewall.registerExecutor({
			toolClass: tc,
			async execute(toolCall) {
				const taintLabels: TaintLabel[] = autoTaint
					? deriveTaintLabels(tc, toolCall.parameters)
					: [];
				return {
					callId: toolCall.id,
					success: true,
					data: null,
					durationMs: 0,
					taintLabels,
				};
			},
		});
	}
}

/** Derive taint labels from tool class and parameters. */
function deriveTaintLabels(
	toolClass: string,
	parameters: Record<string, unknown>,
): TaintLabel[] {
	const now = new Date().toISOString();
	if (toolClass === 'http') {
		let hostname = 'unknown';
		if (typeof parameters.url === 'string') {
			try {
				hostname = new URL(parameters.url).hostname;
			} catch {
				// invalid URL, keep 'unknown'
			}
		}
		return [{ source: 'web', origin: hostname, confidence: 0.9, addedAt: now }];
	}
	if (toolClass === 'database') {
		return [{ source: 'tool-output', origin: 'database', confidence: 0.8, addedAt: now }];
	}
	return [];
}
