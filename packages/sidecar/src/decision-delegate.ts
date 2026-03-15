import { createHash, randomBytes } from "node:crypto";
import type { DecisionVerdict, TaintLabel, ToolClass } from "@arikernel/core";
import {
	DecisionVerifier,
	NonceStore,
	type DecisionResponse,
} from "@arikernel/control-plane";

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
	decisionId: string;
	policyHash: string;
	kernelBuild: string;
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
	/**
	 * Hex-encoded Ed25519 public key of the control plane (64 hex chars / 32 bytes).
	 * When provided, the delegate verifies the Ed25519 signature and nonce on every
	 * decision receipt. Verification failure causes the request to fail closed (return null).
	 * Strongly recommended for production deployments.
	 */
	controlPlanePublicKey?: string;
}

/**
 * Delegates policy decisions to a remote control plane via HTTP.
 *
 * Called by the sidecar router before local execution when decisionMode is 'remote'.
 * If the control plane denies the call, the sidecar short-circuits without executing.
 * When a public key is configured, every response is verified before being trusted.
 */
export class DecisionDelegate {
	private readonly endpoint: string;
	private readonly headers: Record<string, string>;
	private readonly timeoutMs: number;
	private readonly verifier: DecisionVerifier | undefined;
	private readonly nonceStore: NonceStore | undefined;

	/**
	 * Compute SHA-256 hash of canonical request fields for receipt binding.
	 */
	static computeRequestHash(fields: {
		principalId: string;
		toolClass: string;
		action: string;
		parameters: Record<string, unknown>;
		runId: string;
		requestNonce: string;
	}): string {
		const canonical = JSON.stringify(
			{
				action: fields.action,
				parameters: fields.parameters,
				principalId: fields.principalId,
				requestNonce: fields.requestNonce,
				runId: fields.runId,
				toolClass: fields.toolClass,
			},
			Object.keys({
				action: 1, parameters: 1, principalId: 1,
				requestNonce: 1, runId: 1, toolClass: 1,
			}).sort(),
		);
		return createHash("sha256").update(canonical).digest("hex");
	}

	constructor(config: RemoteDecisionConfig) {
		this.endpoint = config.controlPlaneUrl.replace(/\/$/, "");
		this.timeoutMs = config.controlPlaneTimeoutMs ?? 5000;
		this.headers = { "Content-Type": "application/json" };
		if (config.controlPlaneAuthToken) {
			this.headers.Authorization = `Bearer ${config.controlPlaneAuthToken}`;
		}
		if (config.controlPlanePublicKey) {
			this.verifier = new DecisionVerifier(config.controlPlanePublicKey);
			this.nonceStore = new NonceStore();
		}
	}

	/**
	 * Request a policy decision from the remote control plane.
	 *
	 * When a public key is configured, the response is verified against the
	 * Ed25519 signature and nonce before being returned. Verification failure
	 * returns null (fail closed — caller treats as unreachable).
	 *
	 * Returns null if the control plane is unreachable or verification fails.
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

			const data = (await res.json()) as DecisionResponse;

			// Verify receipt integrity when public key is configured
			if (this.verifier) {
				const valid = this.verifier.verify(data, this.nonceStore);
				if (!valid) {
					return null;
				}

				// Verify request binding: requestNonce must echo back
				if (data.requestNonce !== requestNonce) {
					return null;
				}

				// Verify requestHash binds receipt to the exact request parameters
				if (!data.requestHash) {
					return null; // requestHash is mandatory when verifier is configured
				}
				const expectedHash = DecisionDelegate.computeRequestHash({
					principalId: params.principalId,
					toolClass: params.toolClass,
					action: params.action,
					parameters: params.parameters,
					runId: params.runId,
					requestNonce,
				});
				if (data.requestHash !== expectedHash) {
					return null;
				}
			}

			return {
				verdict: data.decision,
				reason: data.reason,
				signature: data.signature,
				nonce: data.nonce,
				policyVersion: data.policyVersion,
				decisionId: data.decisionId,
				policyHash: data.policyHash,
				kernelBuild: data.kernelBuild,
				taintLabels: data.taintLabels,
			};
		} catch {
			// Control plane unreachable — caller decides whether to fail open or closed
			return null;
		}
	}
}
