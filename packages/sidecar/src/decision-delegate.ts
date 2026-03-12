import { randomBytes } from "node:crypto";
import type { DecisionVerdict, TaintLabel, ToolClass } from "@arikernel/core";

/**
 * Decision mode: local evaluation (default) or remote via control plane.
 */
export type DecisionMode = "local" | "remote";

/**
 * Result from a remote decision request.
 */
export interface RemoteDecision {
	verdict: DecisionVerdict;
	reason: string;
	signature: string;
	nonce: string;
	policyVersion: string;
	taintLabels: TaintLabel[];
}

/**
 * Configuration for remote decision delegation.
 */
export interface RemoteDecisionConfig {
	/** Control plane base URL. Required when decisionMode is 'remote'. */
	controlPlaneUrl: string;
	/** Bearer token for authenticating with the control plane. */
	controlPlaneAuthToken?: string;
	/** Request timeout in milliseconds. Default: 5000 */
	controlPlaneTimeoutMs?: number;
}

/**
 * Delegates policy decisions to a remote control plane via HTTP.
 *
 * Called by the sidecar router before local execution when decisionMode is 'remote'.
 * If the control plane denies the call, the sidecar short-circuits without executing.
 */
export class DecisionDelegate {
	private readonly endpoint: string;
	private readonly headers: Record<string, string>;
	private readonly timeoutMs: number;

	constructor(config: RemoteDecisionConfig) {
		this.endpoint = config.controlPlaneUrl.replace(/\/$/, "");
		this.timeoutMs = config.controlPlaneTimeoutMs ?? 5000;
		this.headers = { "Content-Type": "application/json" };
		if (config.controlPlaneAuthToken) {
			this.headers.Authorization = `Bearer ${config.controlPlaneAuthToken}`;
		}
	}

	/**
	 * Request a policy decision from the remote control plane.
	 * Returns null if the control plane is unreachable (fail-open is caller's choice).
	 */
	async requestDecision(params: {
		principalId: string;
		toolClass: ToolClass;
		action: string;
		parameters: Record<string, unknown>;
		taintLabels: TaintLabel[];
		runId: string;
	}): Promise<RemoteDecision | null> {
		try {
			const requestNonce = randomBytes(16).toString("hex");
			const res = await fetch(`${this.endpoint}/decision`, {
				method: "POST",
				headers: this.headers,
				body: JSON.stringify({
					...params,
					requestNonce,
					timestamp: new Date().toISOString(),
				}),
				signal: AbortSignal.timeout(this.timeoutMs),
			});

			if (!res.ok) {
				return null;
			}

			const data = (await res.json()) as RemoteDecision;
			return data;
		} catch {
			// Control plane unreachable — caller decides whether to fail open or closed
			return null;
		}
	}
}
