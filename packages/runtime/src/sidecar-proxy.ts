/**
 * SidecarProxyExecutor — Delegates tool execution to the sidecar HTTP API.
 *
 * When the runtime operates in "sidecar" enforcement mode, the Firewall acts
 * as a thin client. The sidecar is the single authoritative enforcement
 * boundary — all policy evaluation, token management, behavioral rules,
 * taint tracking, and tool execution happen in the sidecar process.
 *
 * Flow: Agent → Firewall.execute() → SidecarHttpClient → Sidecar HTTP → Real Executor
 *
 * The host process performs NO local policy evaluation in sidecar mode.
 * SidecarProxyExecutor is retained for backward compatibility but the
 * primary path uses SidecarHttpClient directly from Firewall.
 *
 * IMPORTANT: Security denials (HTTP 403 or allowed=false) are raised as
 * ToolCallDeniedError so the host can track them for observability.
 * Tool execution failures (allowed=true, success=false) are returned as
 * ToolResult with success=false, which does NOT represent a security denial.
 */

import type {
	CapabilityClass,
	Decision,
	IssuanceDecision,
	TaintLabel,
	ToolCall,
	ToolCallRequest,
	ToolResult,
} from "@arikernel/core";
import { ToolCallDeniedError, generateId, now } from "@arikernel/core";
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

// ── SidecarHttpClient ─────────────────────────────────────────────────────────
//
// Thin HTTP client used by Firewall in sidecar mode. Routes requestCapability()
// and execute() directly to the sidecar over HTTP. No local policy evaluation,
// no local token store, no local behavioral rules — the sidecar is the single
// authoritative enforcement boundary.

export interface SidecarHttpClientConfig {
	baseUrl: string;
	principalId: string;
	authToken?: string;
}

export class SidecarHttpClient {
	private readonly endpoint: string;
	private readonly principalId: string;
	private readonly headers: Record<string, string>;

	constructor(config: SidecarHttpClientConfig) {
		this.endpoint = config.baseUrl.replace(/\/$/, "");
		this.principalId = config.principalId;
		this.headers = { "Content-Type": "application/json" };
		if (config.authToken) {
			this.headers.Authorization = `Bearer ${config.authToken}`;
		}
	}

	/**
	 * Request a capability grant from the sidecar.
	 *
	 * The sidecar evaluates policy, checks principal capabilities, and
	 * manages the authoritative token store. The returned grantId can be
	 * forwarded to execute() calls.
	 */
	async requestCapability(
		capabilityClass: CapabilityClass,
		options?: {
			constraints?: Record<string, unknown>;
			taintLabels?: TaintLabel[];
			justification?: string;
		},
	): Promise<IssuanceDecision> {
		const body: Record<string, unknown> = {
			principalId: this.principalId,
			capabilityClass,
		};
		if (options?.constraints) body.constraints = options.constraints;
		if (options?.justification) body.justification = options.justification;

		const res = await fetch(`${this.endpoint}/request-capability`, {
			method: "POST",
			headers: this.headers,
			body: JSON.stringify(body),
		});

		const json = (await res.json()) as {
			granted: boolean;
			grantId?: string;
			capabilityToken?: string;
			reason?: string;
		};

		const requestId = generateId();
		const ts = now();

		if (!json.granted) {
			return {
				requestId,
				granted: false,
				reason: json.reason ?? "Denied by sidecar",
				taintLabels: options?.taintLabels ?? [],
				timestamp: ts,
			};
		}

		return {
			requestId,
			granted: true,
			grant: {
				id: json.grantId ?? generateId(),
				requestId,
				principalId: this.principalId,
				capabilityClass,
				constraints: (options?.constraints ?? {}) as import("@arikernel/core").CapabilityConstraint,
				lease: {
					issuedAt: ts,
					expiresAt: "", // managed by sidecar
					maxCalls: 0, // managed by sidecar
					callsUsed: 0,
				},
				taintContext: options?.taintLabels ?? [],
				revoked: false,
				nonce: "",
			},
			reason: json.reason ?? "Granted by sidecar",
			taintLabels: options?.taintLabels ?? [],
			timestamp: ts,
		};
	}

	/**
	 * Execute a tool call through the sidecar.
	 *
	 * The sidecar performs all policy evaluation, token enforcement, behavioral
	 * rules, taint tracking, executes the tool via its own executors, and records
	 * the audit event. The host process does NONE of this locally.
	 *
	 * Returns ToolResult on success. Throws ToolCallDeniedError on denial.
	 */
	async execute(request: ToolCallRequest): Promise<ToolResult> {
		const body: Record<string, unknown> = {
			principalId: this.principalId,
			toolClass: request.toolClass,
			action: request.action,
			params: request.parameters,
		};
		if (request.taintLabels && request.taintLabels.length > 0) {
			body.taint = request.taintLabels;
		}
		if (request.grantId) {
			body.grantId = request.grantId;
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
			resultTaint?: TaintLabel[];
			callId?: string;
		};

		const callId = json.callId ?? generateId();

		if (res.status === 403 || !json.allowed) {
			const toolCall: ToolCall = {
				id: callId,
				runId: "",
				sequence: 0,
				timestamp: now(),
				principalId: this.principalId,
				toolClass: request.toolClass,
				action: request.action,
				parameters: request.parameters,
				taintLabels: request.taintLabels ?? [],
				grantId: request.grantId,
			};
			const decision: Decision = {
				verdict: "deny",
				matchedRule: null,
				reason: json.error ?? "Sidecar denied the action",
				taintLabels: request.taintLabels ?? [],
				timestamp: now(),
			};
			throw new ToolCallDeniedError(toolCall, decision);
		}

		const success = json.success ?? true;
		return {
			callId,
			success,
			data: success ? json.result : undefined,
			error: success ? undefined : (json.error ?? "Tool execution failed"),
			durationMs: 0,
			taintLabels: json.resultTaint ?? [],
		};
	}
}
