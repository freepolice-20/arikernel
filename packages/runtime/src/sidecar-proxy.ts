/**
 * SidecarProxyExecutor — Delegates tool execution to the sidecar HTTP API.
 *
 * When the runtime operates in "sidecar" enforcement mode, real tool executors
 * are replaced with these proxies. The host process never executes tools
 * directly — the sidecar is the authoritative enforcement boundary.
 *
 * Flow: Agent → Firewall (local policy check) → SidecarProxyExecutor → Sidecar HTTP → Real Executor
 *
 * IMPORTANT: Security denials (HTTP 403 or allowed=false) are raised as
 * ToolCallDeniedError so the host pipeline correctly tracks them in denial
 * counters and quarantine logic. Tool execution failures (allowed=true,
 * success=false — e.g. file not found) are returned as ToolResult with
 * success=false, which does NOT increment denial counters.
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
 * Response classification:
 * - HTTP 403 or allowed=false → security denial → ToolCallDeniedError
 * - HTTP 200, allowed=true, success=false → tool failure → ToolResult{success:false}
 * - HTTP 200, allowed=true, success=true → success → ToolResult{success:true}
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
		const capToken = (toolCall as unknown as Record<string, unknown>).capabilityToken;
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
			success?: boolean;
			result?: unknown;
			error?: string;
			resultTaint?: import("@arikernel/core").TaintLabel[];
			callId?: string;
		};

		// Security denial: HTTP 403 or explicit allowed=false.
		// Raise as ToolCallDeniedError so the host pipeline correctly:
		// - increments denied action counters
		// - pushes tool_call_denied events
		// - triggers quarantine logic
		// - produces accurate audit records
		if (res.status === 403 || !json.allowed) {
			const decision: Decision = {
				verdict: "deny",
				matchedRule: null,
				reason: json.error ?? "Sidecar denied the action",
				taintLabels: toolCall.taintLabels,
				timestamp: now(),
			};
			throw new ToolCallDeniedError(toolCall, decision);
		}

		// Action was permitted. success reflects whether the tool itself
		// succeeded operationally (e.g. file exists vs ENOENT).
		// Tool failures are NOT security denials.
		const success = json.success ?? true;
		return {
			callId: json.callId ?? toolCall.id,
			success,
			data: success ? json.result : undefined,
			error: success ? undefined : (json.error ?? "Tool execution failed"),
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
