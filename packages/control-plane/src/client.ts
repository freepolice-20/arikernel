import { randomBytes } from "node:crypto";
import type { TaintLabel, ToolClass } from "@arikernel/core";
import type { DecisionResponse, TaintQueryResponse } from "./types.js";

export interface ControlPlaneClientOptions {
	/** Base URL of the control plane. Default: http://localhost:9090 */
	baseUrl?: string;
	/** Bearer token for authentication */
	authToken?: string;
	/** Request timeout in milliseconds. Default: 5000 */
	timeoutMs?: number;
}

/**
 * HTTP client for the AriKernel control plane.
 * Used by sidecars to delegate policy decisions remotely.
 */
export class ControlPlaneClient {
	private readonly endpoint: string;
	private readonly headers: Record<string, string>;
	private readonly timeoutMs: number;

	constructor(options: ControlPlaneClientOptions = {}) {
		this.endpoint = (options.baseUrl ?? "http://localhost:9090").replace(/\/$/, "");
		this.timeoutMs = options.timeoutMs ?? 5000;
		this.headers = { "Content-Type": "application/json" };
		if (options.authToken) {
			this.headers.Authorization = `Bearer ${options.authToken}`;
		}
	}

	/**
	 * Request a policy decision from the control plane.
	 */
	async requestDecision(params: {
		principalId: string;
		toolClass: ToolClass;
		action: string;
		parameters: Record<string, unknown>;
		taintLabels: TaintLabel[];
		runId: string;
		timestamp?: string;
		requestNonce?: string;
	}): Promise<DecisionResponse> {
		return this.post("/decision", {
			...params,
			timestamp: params.timestamp ?? new Date().toISOString(),
			requestNonce: params.requestNonce ?? randomBytes(16).toString("hex"),
		});
	}

	/**
	 * Register taint labels in the global registry.
	 */
	async registerTaint(params: {
		principalId: string;
		runId: string;
		labels: TaintLabel[];
		resourceIds?: string[];
	}): Promise<{ registered: boolean; count: number }> {
		return this.post("/taint/register", params);
	}

	/**
	 * Query taint labels for a specific resource.
	 */
	async queryTaint(resourceId: string): Promise<TaintQueryResponse> {
		return this.post("/taint/query", { resourceId });
	}

	/**
	 * Health check.
	 */
	async health(): Promise<boolean> {
		try {
			const res = await fetch(`${this.endpoint}/health`, {
				signal: AbortSignal.timeout(this.timeoutMs),
			});
			return res.ok;
		} catch {
			return false;
		}
	}

	private async post<T>(path: string, body: unknown): Promise<T> {
		const res = await fetch(`${this.endpoint}${path}`, {
			method: "POST",
			headers: this.headers,
			body: JSON.stringify(body),
			signal: AbortSignal.timeout(this.timeoutMs),
		});

		const data = await res.json();

		if (!res.ok) {
			throw new ControlPlaneError(
				(data as { error?: string }).error ?? `HTTP ${res.status}`,
				res.status,
			);
		}

		return data as T;
	}
}

export class ControlPlaneError extends Error {
	constructor(
		message: string,
		readonly statusCode: number,
	) {
		super(message);
		this.name = "ControlPlaneError";
	}
}
