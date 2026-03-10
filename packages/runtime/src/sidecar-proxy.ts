/**
 * SidecarProxyExecutor — Delegates tool execution to the sidecar HTTP API.
 *
 * When the runtime operates in "sidecar" enforcement mode, real tool executors
 * are replaced with these proxies. The host process never executes tools
 * directly — the sidecar is the authoritative enforcement boundary.
 *
 * Flow: Agent → Firewall (local policy check) → SidecarProxyExecutor → Sidecar HTTP → Real Executor
 */

import type { ToolCall, ToolResult } from "@arikernel/core";
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
		const body = {
			principalId: this.principalId,
			toolClass: this.toolClass,
			action: toolCall.action,
			params: toolCall.parameters,
			taint: toolCall.taintLabels.length > 0 ? toolCall.taintLabels : undefined,
		};

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

		return {
			callId: json.callId ?? toolCall.id,
			success: json.allowed,
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
