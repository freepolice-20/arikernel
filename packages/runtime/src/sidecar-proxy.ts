/**
 * SidecarProxyExecutor — Delegates tool execution to the sidecar HTTP API.
 *
 * When the runtime operates in "sidecar" enforcement mode, real tool executors
 * are replaced with these proxies. The host process never executes tools
 * directly — the sidecar is the authoritative enforcement boundary.
 *
 * Flow: Agent → Firewall (local policy check) → SidecarProxyExecutor → Sidecar HTTP → Real Executor
 *
 * IMPORTANT: Sidecar denials are raised as ToolCallDeniedError so the host
 * pipeline correctly classifies them as security denials (not tool failures).
 * Grant IDs and capability tokens are forwarded to the sidecar so it can
 * validate them server-side.
 */

import type { Decision, ToolCall, ToolResult } from "@arikernel/core";
import { ToolCallDeniedError, now } from "@arikernel/core";
import type { ToolExecutor } from "@arikernel/tool-executors";

export interface SidecarProxyConfig {
	/** Base URL of the sidecar server. Default: http://localhost:8787 */
	baseUrl?: string;
	/** principalId to use for proxied calls */
	principalId: string;
	/** Bearer token for sidecar authentication */
	authToken?: string;
}

/**
 * A ToolExecutor that proxies all execution through the sidecar HTTP API.
 * The host process performs no direct tool execution — the sidecar owns
 * the real executors and is the sole execution boundary.
 *
 * Sidecar denials are raised as ToolCallDeniedError (not returned as
 * ToolResult.success=false) so the host pipeline correctly tracks denials
 * in audit logs, run-state counters, and behavioral quarantine logic.
 */
export class SidecarProxyExecutor implements ToolExecutor {
	readonly toolClass: string;
	private readonly endpoint: string;
	private readonly principalId: string;
	private readonly headers: Record<string, string>;

	constructor(toolClass: string, config: SidecarProxyConfig) {
		this.toolClass = toolClass;
		this.endpoint = (config.baseUrl ?? "http://localhost:8787").replace(/\/$/, "");
		this.principalId = config.principalId;
		this.headers = { "Content-Type": "application/json" };
		if (config.authToken) {
			this.headers.Authorization = `Bearer ${config.authToken}`;
		}
	}

	async execute(toolCall: ToolCall): Promise<ToolResult> {
		const body: Record<string, unknown> = {
			principalId: this.principalId,
			toolClass: this.toolClass,
			action: toolCall.action,
			params: toolCall.parameters,
			taint: toolCall.taintLabels.length > 0 ? toolCall.taintLabels : undefined,
		};

		// Forward grant ID so the sidecar can validate capability tokens server-side.
		if (toolCall.grantId) {
			body.grantId = toolCall.grantId;
		}

		// Forward serialized capability token if present (for cryptographic verification).
		const capToken = (toolCall as Record<string, unknown>).capabilityToken;
		if (typeof capToken === "string") {
			body.capabilityToken = capToken;
		}

		const res = await fetch(`${this.endpoint}/execute`, {
			method: "POST",
			headers: this.headers,
			body: JSON.stringify(body),
		});

		const json = (await res.json()) as {
			allowed: boolean;
			result?: unknown;
			error?: string;
			resultTaint?: import("@arikernel/core").TaintLabel[];
			callId?: string;
		};

		// Sidecar denied the action — raise as a security denial, not a tool failure.
		// This ensures the host pipeline correctly:
		// - increments denied action counters
		// - pushes tool_call_denied events
		// - triggers quarantine logic
		// - produces accurate audit records
		if (!json.allowed) {
			const decision: Decision = {
				verdict: "deny",
				matchedRule: null,
				reason: json.error ?? "Sidecar denied the action",
				taintLabels: toolCall.taintLabels,
				timestamp: now(),
			};
			throw new ToolCallDeniedError(toolCall, decision);
		}

		return {
			callId: json.callId ?? toolCall.id,
			success: true,
			data: json.result,
			error: json.error,
			durationMs: 0,
			taintLabels: json.resultTaint ?? [],
		};
	}
}

/** The tool classes that need proxy executors in sidecar mode. */
const PROXY_TOOL_CLASSES = ["http", "file", "shell", "database", "retrieval"] as const;

/**
 * Create proxy executors for all tool classes, pointing at the sidecar.
 */
export function createSidecarProxies(config: SidecarProxyConfig): SidecarProxyExecutor[] {
	return PROXY_TOOL_CLASSES.map((tc) => new SidecarProxyExecutor(tc, config));
}
