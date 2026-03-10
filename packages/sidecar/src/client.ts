import type { TaintLabel } from "@arikernel/core";
import type { ExecuteRequest, ExecuteResponse, StatusResponse } from "./types.js";

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
	private readonly baseUrl: string;
	private readonly principalId: string;
	private readonly headers: Record<string, string>;

	constructor(options: SidecarClientOptions) {
		this.baseUrl = (options.baseUrl ?? "http://localhost:8787").replace(/\/$/, "");
		this.principalId = options.principalId;
		this.headers = { "Content-Type": "application/json" };
		if (options.authToken) {
			this.headers.Authorization = `Bearer ${options.authToken}`;
		}
	}

	async execute(
		toolClass: ExecuteRequest["toolClass"],
		action: string,
		params: Record<string, unknown>,
		taint?: TaintLabel[],
	): Promise<ExecuteResponse> {
		const body: ExecuteRequest = {
			principalId: this.principalId,
			toolClass,
			action,
			params,
			taint,
		};

		const res = await fetch(`${this.baseUrl}/execute`, {
			method: "POST",
			headers: this.headers,
			body: JSON.stringify(body),
		});

		return res.json() as Promise<ExecuteResponse>;
	}

	/** Query this principal's enforcement state (quarantine, counters). */
	async status(): Promise<StatusResponse> {
		const res = await fetch(`${this.baseUrl}/status`, {
			method: "POST",
			headers: this.headers,
			body: JSON.stringify({ principalId: this.principalId }),
		});
		return res.json() as Promise<StatusResponse>;
	}

	async health(): Promise<boolean> {
		try {
			const res = await fetch(`${this.baseUrl}/health`);
			return res.ok;
		} catch {
			return false;
		}
	}
}
