import { type CapabilityConstraint, type TaintLabel, deriveCapabilityClass } from "@arikernel/core";
import type { ExecuteRequest, ExecuteResponse, RequestCapabilityResponse, StatusResponse } from "./types.js";

export interface SidecarClientOptions {
	/** Base URL of the sidecar server. Default: http://localhost:8787 */
	baseUrl?: string;
	/** principalId to use for all calls from this client instance */
	principalId: string;
	/** Bearer token for authentication (must match server's authToken) */
	authToken?: string;
}

/**
 * Thin HTTP client for the AriKernel sidecar.
 * Agents use this instead of calling tools directly — the sidecar enforces policy.
 */
export class SidecarClient {
	/** @internal Used by SidecarGuard to exempt sidecar-bound requests. */
	readonly endpoint: string;
	private readonly principalId: string;
	private readonly headers: Record<string, string>;

	constructor(options: SidecarClientOptions) {
		this.endpoint = (options.baseUrl ?? "http://localhost:8787").replace(/\/$/, "");
		this.principalId = options.principalId;
		this.headers = { "Content-Type": "application/json" };
		if (options.authToken) {
			this.headers.Authorization = `Bearer ${options.authToken}`;
		}

		// SECURITY: Warn if endpoint is non-localhost and non-HTTPS.
		// Credentials and tool calls sent over plain HTTP to remote hosts
		// are vulnerable to interception.
		try {
			const url = new URL(this.endpoint);
			const isLocalhost = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "::1";
			if (!isLocalhost && url.protocol !== "https:") {
				console.warn(
					`[AriKernel] WARNING: Sidecar endpoint '${this.endpoint}' is non-localhost and non-HTTPS. ` +
					"Credentials and tool calls may be transmitted in plaintext. Use HTTPS for remote sidecar connections.",
				);
			}
		} catch {
			// Invalid URL — will fail on first request anyway
		}
	}

	async execute(
		toolClass: ExecuteRequest["toolClass"],
		action: string,
		params: Record<string, unknown>,
		taint?: TaintLabel[],
		capabilityToken?: string,
	): Promise<ExecuteResponse> {
		const body: ExecuteRequest = {
			principalId: this.principalId,
			toolClass,
			action,
			params,
			taint,
			capabilityToken,
		};

		const res = await fetch(`${this.endpoint}/execute`, {
			method: "POST",
			headers: this.headers,
			body: JSON.stringify(body),
		});

		return res.json() as Promise<ExecuteResponse>;
	}

	/**
	 * Request a capability and execute in one step.
	 * Requests a signed capability token, then immediately uses it to execute.
	 * This is the recommended secure workflow for agents.
	 */
	async secureExecute(
		toolClass: ExecuteRequest["toolClass"],
		action: string,
		params: Record<string, unknown>,
		taint?: TaintLabel[],
	): Promise<ExecuteResponse> {
		const cap = await this.requestCapability(
			deriveCapabilityClass(toolClass, action),
		);
		if (!cap.granted) {
			return { allowed: false, error: cap.reason ?? "Capability denied" };
		}
		return this.execute(toolClass, action, params, taint, cap.capabilityToken);
	}

	/**
	 * Request a capability grant from the sidecar.
	 * Returns a grantId that can be passed to execute() for protected actions.
	 */
	async requestCapability(
		capabilityClass: string,
		options?: {
			constraints?: CapabilityConstraint;
			justification?: string;
		},
	): Promise<RequestCapabilityResponse> {
		const body = {
			principalId: this.principalId,
			capabilityClass,
			constraints: options?.constraints,
			justification: options?.justification,
		};

		const res = await fetch(`${this.endpoint}/request-capability`, {
			method: "POST",
			headers: this.headers,
			body: JSON.stringify(body),
		});

		return res.json() as Promise<RequestCapabilityResponse>;
	}

	/** Query this principal's enforcement state (quarantine, counters). */
	async status(): Promise<StatusResponse> {
		const res = await fetch(`${this.endpoint}/status`, {
			method: "POST",
			headers: this.headers,
			body: JSON.stringify({ principalId: this.principalId }),
		});
		return res.json() as Promise<StatusResponse>;
	}

	async health(): Promise<boolean> {
		try {
			const res = await fetch(`${this.endpoint}/health`);
			return res.ok;
		} catch {
			return false;
		}
	}
}
