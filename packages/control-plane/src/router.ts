import { createHash, timingSafeEqual as cryptoTimingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { TOOL_CLASSES, now } from "@arikernel/core";
import type { TaintLabel, ToolClass } from "@arikernel/core";
import type { PolicyEngine } from "@arikernel/policy-engine";
import type { ControlPlaneAuditStore } from "./audit-store.js";
import type { DecisionSigner, NonceStore } from "./signer.js";
import type { GlobalTaintRegistry } from "./taint-registry.js";
import type {
	ControlPlaneConfig,
	DecisionRequest,
	DecisionResponse,
	TaintQueryRequest,
	TaintQueryResponse,
	TaintRegistrationRequest,
} from "./types.js";

const MAX_BODY_BYTES = 1_048_576;

export async function handleDecision(
	req: IncomingMessage,
	res: ServerResponse,
	engine: PolicyEngine,
	signer: DecisionSigner,
	taintRegistry: GlobalTaintRegistry,
	config: ControlPlaneConfig,
	auditStore?: ControlPlaneAuditStore,
	policyHash?: string,
	requestNonceStore?: NonceStore,
): Promise<void> {
	let body: unknown;
	try {
		body = await readBody(req);
	} catch (e) {
		const msg = (e as Error).message;
		return jsonResponse(res, msg === "Request body too large" ? 413 : 400, { error: msg });
	}

	let decReq: DecisionRequest;
	try {
		decReq = validateDecisionRequest(body);
	} catch (e) {
		return jsonResponse(res, 400, { error: (e as Error).message });
	}

	// Request-level replay protection: requestNonce is mandatory to prevent
	// decision replay attacks (attacker stripping nonce to get unbound signatures).
	if (!decReq.requestNonce) {
		return jsonResponse(res, 400, {
			error: "requestNonce is required — decisions must be bound to the originating request",
		});
	}
	if (requestNonceStore) {
		if (!requestNonceStore.claim(decReq.requestNonce)) {
			return jsonResponse(res, 409, {
				error: "Duplicate requestNonce — request already processed",
			});
		}
	}

	// Enrich taint labels with any global registry taints for resources in parameters
	const resourceIds = extractResourceIds(decReq.parameters);
	const globalTaints: TaintLabel[] = [];
	for (const rid of resourceIds) {
		globalTaints.push(...taintRegistry.queryResource(rid));
	}
	const mergedTaints = dedup([...decReq.taintLabels, ...globalTaints]);

	// Build a synthetic ToolCall for the policy engine
	const toolCall = {
		id: `cp-${Date.now()}`,
		runId: decReq.runId,
		sequence: 0,
		timestamp: now(),
		principalId: decReq.principalId,
		toolClass: decReq.toolClass,
		action: decReq.action.toLowerCase(),
		parameters: decReq.parameters,
		taintLabels: mergedTaints,
	};

	// Evaluate against policy engine (uses capabilities from policy rules only)
	// Control plane evaluates rules directly — capability grants are managed by sidecars
	const defaultCapabilities = [{ toolClass: decReq.toolClass, actions: [] }];
	const decision = engine.evaluate(toolCall, mergedTaints, defaultCapabilities);

	// Register any taint labels in the global registry
	if (mergedTaints.length > 0) {
		taintRegistry.register(decReq.principalId, decReq.runId, mergedTaints, resourceIds);
	}

	// Compute requestHash binding the decision to the original request
	let requestHash: string | undefined;
	if (decReq.requestNonce) {
		const hashPayload = JSON.stringify(
			{
				action: decReq.action,
				parameters: decReq.parameters,
				principalId: decReq.principalId,
				requestNonce: decReq.requestNonce,
				runId: decReq.runId,
				toolClass: decReq.toolClass,
			},
			Object.keys({
				action: 1,
				parameters: 1,
				principalId: 1,
				requestNonce: 1,
				runId: 1,
				toolClass: 1,
			}).sort(),
		);
		requestHash = createHash("sha256").update(hashPayload).digest("hex");
	}

	const effectivePolicyHash = policyHash ?? "0000000000000000";
	const response = signer.sign({
		decision: decision.verdict,
		reason: decision.reason,
		policyVersion: config.policyVersion ?? "1.0.0",
		policyHash: effectivePolicyHash,
		kernelBuild: config.kernelBuild ?? "arikernel-cp-0.1.2",
		timestamp: decision.timestamp,
		matchedRule: decision.matchedRule ?? undefined,
		taintLabels: mergedTaints,
		requestHash,
		requestNonce: decReq.requestNonce,
	});

	auditStore?.record({
		principalId: decReq.principalId,
		toolClass: decReq.toolClass,
		action: decReq.action,
		decision: decision.verdict,
		reason: decision.reason,
		timestamp: decision.timestamp,
		policyVersion: config.policyVersion ?? "1.0.0",
		runId: decReq.runId,
		signature: response.signature,
	});

	return jsonResponse(res, 200, response);
}

export async function handleTaintRegister(
	req: IncomingMessage,
	res: ServerResponse,
	taintRegistry: GlobalTaintRegistry,
): Promise<void> {
	let body: unknown;
	try {
		body = await readBody(req);
	} catch (e) {
		return jsonResponse(res, 400, { error: (e as Error).message });
	}

	const raw = body as Record<string, unknown>;
	if (!raw || typeof raw !== "object") {
		return jsonResponse(res, 400, { error: "Request body must be a JSON object" });
	}
	if (typeof raw.principalId !== "string" || !raw.principalId) {
		return jsonResponse(res, 400, { error: "principalId must be a non-empty string" });
	}
	if (typeof raw.runId !== "string" || !raw.runId) {
		return jsonResponse(res, 400, { error: "runId must be a non-empty string" });
	}
	if (!Array.isArray(raw.labels) || raw.labels.length === 0) {
		return jsonResponse(res, 400, { error: "labels must be a non-empty array" });
	}

	const registration = raw as unknown as TaintRegistrationRequest;
	const resourceIds = Array.isArray(raw.resourceIds) ? (raw.resourceIds as string[]) : undefined;

	taintRegistry.register(
		registration.principalId,
		registration.runId,
		registration.labels,
		resourceIds,
	);

	return jsonResponse(res, 200, { registered: true, count: registration.labels.length });
}

export async function handleTaintQuery(
	req: IncomingMessage,
	res: ServerResponse,
	taintRegistry: GlobalTaintRegistry,
): Promise<void> {
	let body: unknown;
	try {
		body = await readBody(req);
	} catch (e) {
		return jsonResponse(res, 400, { error: (e as Error).message });
	}

	const raw = body as Record<string, unknown>;
	if (!raw || typeof raw !== "object" || typeof raw.resourceId !== "string") {
		return jsonResponse(res, 400, { error: "resourceId must be a non-empty string" });
	}

	const labels = taintRegistry.queryResource(raw.resourceId as string);
	const response: TaintQueryResponse = {
		resourceId: raw.resourceId as string,
		labels,
	};

	return jsonResponse(res, 200, response);
}

export function handleHealth(res: ServerResponse): void {
	jsonResponse(res, 200, { status: "ok", service: "arikernel-control-plane" });
}

/**
 * Validate Bearer token. Returns true if rejected (caller returns early).
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

// --- helpers ---

function validateDecisionRequest(body: unknown): DecisionRequest {
	if (!body || typeof body !== "object") {
		throw new Error("Request body must be a JSON object");
	}
	const raw = body as Record<string, unknown>;

	if (typeof raw.principalId !== "string" || !raw.principalId.trim()) {
		throw new Error("principalId must be a non-empty string");
	}
	if (!TOOL_CLASSES.includes(raw.toolClass as never)) {
		throw new Error(`toolClass must be one of: ${TOOL_CLASSES.join(", ")}`);
	}
	if (typeof raw.action !== "string" || !raw.action.trim()) {
		throw new Error("action must be a non-empty string");
	}
	if (
		typeof raw.parameters !== "object" ||
		raw.parameters === null ||
		Array.isArray(raw.parameters)
	) {
		throw new Error("parameters must be a JSON object");
	}
	if (typeof raw.runId !== "string" || !raw.runId.trim()) {
		throw new Error("runId must be a non-empty string");
	}
	if (typeof raw.timestamp !== "string" || !raw.timestamp.trim()) {
		throw new Error("timestamp must be a non-empty ISO 8601 string");
	}

	return {
		principalId: raw.principalId as string,
		toolClass: raw.toolClass as ToolClass,
		action: raw.action as string,
		parameters: raw.parameters as Record<string, unknown>,
		taintLabels: Array.isArray(raw.taintLabels) ? (raw.taintLabels as TaintLabel[]) : [],
		runId: raw.runId as string,
		timestamp: raw.timestamp as string,
		requestNonce: typeof raw.requestNonce === "string" ? raw.requestNonce : "",
	};
}

function extractResourceIds(params: Record<string, unknown>): string[] {
	const ids: string[] = [];
	if (typeof params.url === "string") ids.push(params.url);
	if (typeof params.path === "string") ids.push(params.path);
	if (typeof params.table === "string") ids.push(params.table);
	if (typeof params.database === "string") ids.push(params.database);
	return ids;
}

function dedup(labels: TaintLabel[]): TaintLabel[] {
	const seen = new Set<string>();
	const result: TaintLabel[] = [];
	for (const label of labels) {
		const key = `${label.source}:${label.origin}`;
		if (!seen.has(key)) {
			seen.add(key);
			result.push(label);
		}
	}
	return result;
}

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

function timingSafeEqual(a: string, b: string): boolean {
	const bufA = Buffer.from(a, "utf-8");
	const bufB = Buffer.from(b, "utf-8");
	if (bufA.length !== bufB.length) {
		cryptoTimingSafeEqual(bufA, bufA);
		return false;
	}
	return cryptoTimingSafeEqual(bufA, bufB);
}
