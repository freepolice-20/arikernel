import { timingSafeEqual as cryptoTimingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import {
	ApprovalRequiredError,
	TOOL_CLASSES,
	ToolCallDeniedError,
	deriveCapabilityClass,
	deserializeCapabilityToken,
	serializeCapabilityToken,
	verifyCapabilityToken,
} from "@arikernel/core";
import type { SigningKey } from "@arikernel/core";
import type { DecisionDelegate } from "./decision-delegate.js";
import type { RateLimiter } from "./rate-limiter.js";
import type { PrincipalRegistry } from "./registry.js";
import type { AuthContext } from "./server.js";
import type {
	ExecuteRequest,
	ExecuteResponse,
	PrincipalCredentials,
	RequestCapabilityRequest,
	RequestCapabilityResponse,
	StatusResponse,
} from "./types.js";

/** Maximum request body size (1 MB). Prevents abuse from untrusted clients. */
const MAX_BODY_BYTES = 1_048_576;

async function readBody(req: IncomingMessage): Promise<unknown> {
	return new Promise((resolve, reject) => {
		let body = "";
		let bytes = 0;
		req.on("data", (chunk: Buffer | string) => {
			bytes += typeof chunk === "string" ? Buffer.byteLength(chunk) : chunk.length;
			if (bytes > MAX_BODY_BYTES) {
				req.destroy();
				reject(new Error("Request body too large"));
				return;
			}
			body += chunk;
		});
		req.on("end", () => {
			try {
				resolve(JSON.parse(body));
			} catch {
				reject(new Error("Invalid JSON body"));
			}
		});
		req.on("error", reject);
	});
}

function jsonResponse(res: ServerResponse, status: number, body: unknown): void {
	const payload = JSON.stringify(body);
	res.writeHead(status, {
		"Content-Type": "application/json",
		"Content-Length": Buffer.byteLength(payload),
		Connection: "close",
	});
	res.end(payload);
}

/**
 * Resolve the effective principalId for a request.
 *
 * When `authCtx.authenticated` is true, the principalId was already derived from
 * the API key and is authoritative. If the request body also specifies a principalId,
 * it must match — mismatches are rejected to prevent spoofing.
 *
 * When `authCtx.authenticated` is false (dev mode), the client-supplied principalId
 * from the body is trusted for backward compatibility.
 */
function resolveEffectivePrincipal(
	authCtx: AuthContext,
	bodyPrincipalId: string | undefined,
): { principalId: string; error?: undefined } | { principalId?: undefined; error: string } {
	if (authCtx.authenticated && authCtx.principalId) {
		// In authenticated mode, body principalId is optional but must match if present
		if (bodyPrincipalId && bodyPrincipalId !== authCtx.principalId) {
			return {
				error: `Principal mismatch: authenticated as '${authCtx.principalId}' but request specified '${bodyPrincipalId}'`,
			};
		}
		return { principalId: authCtx.principalId };
	}

	// Dev mode: trust client-supplied principalId
	if (!bodyPrincipalId || !bodyPrincipalId.trim()) {
		return { error: "principalId must be a non-empty string" };
	}
	return { principalId: bodyPrincipalId };
}

function validateExecuteRequest(
	body: unknown,
): Omit<ExecuteRequest, "principalId"> & { principalId?: string } {
	if (!body || typeof body !== "object") throw new Error("Request body must be a JSON object");
	const req = body as Record<string, unknown>;

	// principalId is optional when authenticated via API key
	const principalId = typeof req.principalId === "string" ? req.principalId : undefined;

	if (!TOOL_CLASSES.includes(req.toolClass as never)) {
		throw new Error(`toolClass must be one of: ${TOOL_CLASSES.join(", ")}`);
	}
	if (typeof req.action !== "string" || !req.action.trim()) {
		throw new Error("action must be a non-empty string");
	}
	if (typeof req.params !== "object" || req.params === null || Array.isArray(req.params)) {
		throw new Error("params must be a JSON object");
	}
	if (req.taint !== undefined && !Array.isArray(req.taint)) {
		throw new Error("taint must be an array of TaintLabel objects if provided");
	}

	return {
		principalId,
		toolClass: req.toolClass as ExecuteRequest["toolClass"],
		action: req.action as string,
		params: req.params as Record<string, unknown>,
		taint: req.taint as import("@arikernel/core").TaintLabel[] | undefined,
		grantId: typeof req.grantId === "string" ? req.grantId : undefined,
		capabilityToken: typeof req.capabilityToken === "string" ? req.capabilityToken : undefined,
	};
}

export async function handleExecute(
	req: IncomingMessage,
	res: ServerResponse,
	registry: PrincipalRegistry,
	authCtx: AuthContext,
	rateLimiter: RateLimiter,
	decisionDelegate?: DecisionDelegate,
): Promise<void> {
	let body: unknown;
	try {
		body = await readBody(req);
	} catch (e) {
		const msg = (e as Error).message;
		const status = msg === "Request body too large" ? 413 : 400;
		return jsonResponse(res, status, { allowed: false, error: msg });
	}

	let execReq: ReturnType<typeof validateExecuteRequest>;
	try {
		execReq = validateExecuteRequest(body);
	} catch (e) {
		return jsonResponse(res, 400, { allowed: false, error: (e as Error).message });
	}

	// Resolve effective principalId
	const resolved = resolveEffectivePrincipal(authCtx, execReq.principalId);
	if (resolved.error) {
		return jsonResponse(res, authCtx.authenticated ? 403 : 400, {
			allowed: false,
			error: resolved.error,
		});
	}
	const principalId = resolved.principalId;

	// Rate limiting: check request rate
	const rateCheck = rateLimiter.checkRequestRate(principalId);
	if (!rateCheck.allowed) {
		res.writeHead(429, {
			"Content-Type": "application/json",
			"Retry-After": String(Math.ceil((rateCheck.retryAfterMs ?? 1000) / 1000)),
		});
		res.end(JSON.stringify({ allowed: false, error: "Rate limit exceeded" }));
		return;
	}

	// Rate limiting: check concurrency
	if (!rateLimiter.checkConcurrency(principalId)) {
		return jsonResponse(res, 429, { allowed: false, error: "Concurrent execution limit exceeded" });
	}

	// Rate limiting: check firewall instance limits before creating
	if (
		!registry.has(principalId) &&
		!rateLimiter.checkFirewallLimit(
			registry.principalFirewallCount(principalId),
			registry.totalFirewallCount,
		)
	) {
		return jsonResponse(res, 503, { allowed: false, error: "Firewall instance limit exceeded" });
	}

	const firewall = registry.getOrCreate(principalId);
	const signingKey = registry.getSigningKey();
	const securityMode = registry.getSecurityMode() ?? (signingKey ? "secure" : "dev");

	// Acquire concurrency slot
	rateLimiter.acquire(principalId);

	try {
		// Remote decision mode: delegate policy check to control plane before executing
		if (decisionDelegate) {
			const remoteDecision = await decisionDelegate.requestDecision({
				principalId,
				toolClass: execReq.toolClass,
				action: execReq.action,
				parameters: execReq.params,
				taintLabels: execReq.taint ?? [],
				runId: firewall.runId,
			});

			if (!remoteDecision) {
				// Control plane unreachable — fail closed
				return jsonResponse(res, 503, {
					allowed: false,
					error: "Control plane unreachable — failing closed",
				});
			}

			if (remoteDecision.verdict === "deny") {
				return jsonResponse(res, 403, {
					allowed: false,
					error: remoteDecision.reason,
				});
			}

			if (remoteDecision.verdict === "require-approval") {
				return jsonResponse(res, 403, {
					allowed: false,
					error: `Approval required: ${remoteDecision.reason}`,
				});
			}

			// Control plane allowed — continue to local execution
		}

		// If a client provides a serialized capability token, verify it server-side
		if (execReq.capabilityToken && signingKey) {
			try {
				const token = deserializeCapabilityToken(execReq.capabilityToken);
				const verification = verifyCapabilityToken(token, signingKey);
				if (!verification.valid) {
					return jsonResponse(res, 403, {
						allowed: false,
						error: `Capability token verification failed: ${verification.reason}`,
					});
				}
				const normalizedAction = execReq.action.toLowerCase();
				try {
					const result = await firewall.execute({
						toolClass: execReq.toolClass,
						action: normalizedAction,
						parameters: execReq.params,
						taintLabels: execReq.taint,
						grantId: token.grant.id,
					});

					// Action was permitted (allowed=true). success reflects
					// whether the tool itself succeeded operationally.
					const response: ExecuteResponse = {
						allowed: true,
						success: result.success,
						result: result.success ? result.data : undefined,
						error: result.success ? undefined : result.error,
						resultTaint: result.taintLabels.length > 0 ? result.taintLabels : undefined,
						callId: result.callId,
					};
					return jsonResponse(res, 200, response);
				} catch (e) {
					if (e instanceof ToolCallDeniedError || e instanceof ApprovalRequiredError) {
						return jsonResponse(res, 403, {
							allowed: false,
							error: e.message,
							callId: e.toolCall.id,
						});
					}
					return jsonResponse(res, 500, { allowed: false, error: "Internal server error" });
				}
			} catch {
				return jsonResponse(res, 400, {
					allowed: false,
					error: "Invalid capability token encoding",
				});
			}
		}

		// In 'secure' mode without a client token — auto-issue server-side grant
		if (securityMode === "secure" && !execReq.capabilityToken) {
			// The sidecar itself is trusted, so server-side issuance is acceptable.
		}

		// Precedence: capabilityToken (handled above) > grantId > server auto-issue
		const normalizedAction = execReq.action.toLowerCase();
		let effectiveGrantId: string | undefined;

		if (execReq.grantId) {
			// Client supplied a grantId from a prior /request-capability call
			effectiveGrantId = execReq.grantId;
		} else {
			// Auto-issue: server-side capability issuance (backward compatible)
			const capClass = deriveCapabilityClass(execReq.toolClass, normalizedAction);
			const grant = firewall.requestCapability(capClass);
			effectiveGrantId = grant.granted ? grant.grant?.id : undefined;
		}

		try {
			const result = await firewall.execute({
				toolClass: execReq.toolClass,
				action: normalizedAction,
				parameters: execReq.params,
				taintLabels: execReq.taint,
				grantId: effectiveGrantId,
			});

			// Action was permitted (allowed=true). success reflects
			// whether the tool itself succeeded operationally.
			const response: ExecuteResponse = {
				allowed: true,
				success: result.success,
				result: result.success ? result.data : undefined,
				error: result.success ? undefined : result.error,
				resultTaint: result.taintLabels.length > 0 ? result.taintLabels : undefined,
				callId: result.callId,
			};

			return jsonResponse(res, 200, response);
		} catch (e) {
			if (e instanceof ToolCallDeniedError || e instanceof ApprovalRequiredError) {
				const response: ExecuteResponse = {
					allowed: false,
					error: e.message,
					callId: e.toolCall.id,
				};
				return jsonResponse(res, 403, response);
			}
			return jsonResponse(res, 500, { allowed: false, error: "Internal server error" });
		}
	} finally {
		rateLimiter.release(principalId);
	}
}

/**
 * Handle POST /status — returns principal's quarantine state and run counters.
 */
export async function handleStatus(
	req: IncomingMessage,
	res: ServerResponse,
	registry: PrincipalRegistry,
	authCtx: AuthContext,
): Promise<void> {
	let body: unknown;
	try {
		body = await readBody(req);
	} catch (e) {
		const msg = (e as Error).message;
		const status = msg === "Request body too large" ? 413 : 400;
		return jsonResponse(res, status, { error: msg });
	}

	if (!body || typeof body !== "object") {
		return jsonResponse(res, 400, { error: "Request body must be a JSON object" });
	}

	const raw = body as Record<string, unknown>;
	const bodyPrincipalId = typeof raw.principalId === "string" ? raw.principalId : undefined;

	const resolved = resolveEffectivePrincipal(authCtx, bodyPrincipalId);
	if (resolved.error) {
		return jsonResponse(res, authCtx.authenticated ? 403 : 400, { error: resolved.error });
	}
	const principalId = resolved.principalId;

	if (!registry.has(principalId)) {
		return jsonResponse(res, 404, { error: `Unknown principal: ${principalId}` });
	}

	const firewall = registry.getOrCreate(principalId);
	const counters = firewall.runStateCounters;
	const quarantine = firewall.quarantineInfo;

	const response: StatusResponse = {
		principalId,
		restricted: firewall.isRestricted,
		runId: firewall.runId,
		counters: {
			deniedActions: counters.deniedActions,
			capabilityRequests: counters.capabilityRequests,
			sensitiveFileReadAttempts: counters.sensitiveFileReadAttempts,
			externalEgressAttempts: counters.externalEgressAttempts,
		},
		quarantine: quarantine
			? {
					reason: quarantine.reason,
					triggerType: quarantine.triggerType,
					timestamp: quarantine.timestamp,
				}
			: undefined,
	};

	return jsonResponse(res, 200, response);
}

/**
 * Handle POST /request-capability — request a capability grant from the sidecar.
 */
export async function handleRequestCapability(
	req: IncomingMessage,
	res: ServerResponse,
	registry: PrincipalRegistry,
	authCtx: AuthContext,
	rateLimiter: RateLimiter,
): Promise<void> {
	let body: unknown;
	try {
		body = await readBody(req);
	} catch (e) {
		const msg = (e as Error).message;
		const status = msg === "Request body too large" ? 413 : 400;
		return jsonResponse(res, status, { granted: false, reason: msg });
	}

	if (!body || typeof body !== "object") {
		return jsonResponse(res, 400, { granted: false, reason: "Request body must be a JSON object" });
	}

	const raw = body as Record<string, unknown>;
	const bodyPrincipalId = typeof raw.principalId === "string" ? raw.principalId : undefined;

	const resolved = resolveEffectivePrincipal(authCtx, bodyPrincipalId);
	if (resolved.error) {
		return jsonResponse(res, authCtx.authenticated ? 403 : 400, {
			granted: false,
			reason: resolved.error,
		});
	}
	const principalId = resolved.principalId;

	if (typeof raw.capabilityClass !== "string" || !raw.capabilityClass.trim()) {
		return jsonResponse(res, 400, {
			granted: false,
			reason: "capabilityClass must be a non-empty string",
		});
	}

	// Rate limiting: check request rate
	const rateCheck = rateLimiter.checkRequestRate(principalId);
	if (!rateCheck.allowed) {
		res.writeHead(429, {
			"Content-Type": "application/json",
			"Retry-After": String(Math.ceil((rateCheck.retryAfterMs ?? 1000) / 1000)),
		});
		res.end(JSON.stringify({ granted: false, reason: "Rate limit exceeded" }));
		return;
	}

	// Check firewall limits before creating
	if (
		!registry.has(principalId) &&
		!rateLimiter.checkFirewallLimit(
			registry.principalFirewallCount(principalId),
			registry.totalFirewallCount,
		)
	) {
		return jsonResponse(res, 503, { granted: false, reason: "Firewall instance limit exceeded" });
	}

	const capReq: RequestCapabilityRequest = {
		principalId,
		capabilityClass: raw.capabilityClass as string,
		constraints: raw.constraints as import("@arikernel/core").CapabilityConstraint | undefined,
		justification: raw.justification as string | undefined,
	};

	const firewall = registry.getOrCreate(capReq.principalId);
	const capSigningKey = registry.getSigningKey();
	const decision = firewall.requestCapability(
		capReq.capabilityClass as import("@arikernel/core").CapabilityClass,
		{
			constraints: capReq.constraints,
			justification: capReq.justification,
		},
	);

	let capabilityToken: string | undefined;
	if (decision.granted && decision.grant && capSigningKey) {
		const { createCapabilityToken } = await import("@arikernel/core");
		const signed = createCapabilityToken(decision.grant, capSigningKey);
		capabilityToken = serializeCapabilityToken(signed);
	}

	const response: RequestCapabilityResponse = {
		granted: decision.granted,
		grantId: decision.grant?.id,
		capabilityToken,
		reason: decision.reason,
	};

	return jsonResponse(res, decision.granted ? 200 : 403, response);
}

export function handleHealth(res: ServerResponse): void {
	jsonResponse(res, 200, { status: "ok", service: "arikernel-sidecar" });
}

/**
 * Resolve principalId from API key. Returns the principalId if valid,
 * or undefined if the response was already sent (401/403).
 *
 * Uses constant-time comparison on every registered key to prevent
 * timing-based key enumeration.
 */
export function resolvePrincipal(
	req: IncomingMessage,
	res: ServerResponse,
	principals: PrincipalCredentials,
): string | undefined {
	const auth = req.headers.authorization;
	if (!auth || !auth.startsWith("Bearer ")) {
		jsonResponse(res, 401, { error: "Missing or malformed Authorization header" });
		return undefined;
	}

	const provided = auth.slice(7);

	// Constant-time scan: check every key to prevent timing leaks
	let matched: string | undefined;
	for (const [apiKey, config] of Object.entries(principals)) {
		if (timingSafeEqual(provided, apiKey)) {
			matched = config.principalId;
		}
	}

	if (!matched) {
		jsonResponse(res, 403, { error: "Invalid API key" });
		return undefined;
	}

	return matched;
}

/**
 * Validate Bearer token authentication (shared secret mode).
 * Returns true if rejected (caller should return early), false if passed.
 */
export function rejectUnauthorized(
	req: IncomingMessage,
	res: ServerResponse,
	expectedToken: string,
): boolean {
	const auth = req.headers.authorization;
	if (!auth || !auth.startsWith("Bearer ")) {
		jsonResponse(res, 401, { error: "Missing or malformed Authorization header" });
		return true;
	}

	const provided = auth.slice(7);
	if (!timingSafeEqual(provided, expectedToken)) {
		jsonResponse(res, 403, { error: "Invalid authentication token" });
		return true;
	}

	return false;
}

/** Constant-time string comparison using Node.js crypto.timingSafeEqual. */
function timingSafeEqual(a: string, b: string): boolean {
	const bufA = Buffer.from(a, "utf-8");
	const bufB = Buffer.from(b, "utf-8");
	if (bufA.length !== bufB.length) {
		// Prevent length oracle: compare a against itself to consume constant time,
		// then return false. The allocation cost for different-length inputs is unavoidable.
		cryptoTimingSafeEqual(bufA, bufA);
		return false;
	}
	return cryptoTimingSafeEqual(bufA, bufB);
}
