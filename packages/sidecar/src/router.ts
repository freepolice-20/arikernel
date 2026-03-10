import type { IncomingMessage, ServerResponse } from 'node:http';
import type { PrincipalRegistry } from './registry.js';
import type { ExecuteRequest, ExecuteResponse, StatusResponse } from './types.js';
import { TOOL_CLASSES, ToolCallDeniedError, ApprovalRequiredError, deriveCapabilityClass } from '@arikernel/core';

/** Maximum request body size (1 MB). Prevents abuse from untrusted clients. */
const MAX_BODY_BYTES = 1_048_576;

async function readBody(req: IncomingMessage): Promise<unknown> {
	return new Promise((resolve, reject) => {
		let body = '';
		let bytes = 0;
		req.on('data', (chunk: Buffer | string) => {
			bytes += typeof chunk === 'string' ? Buffer.byteLength(chunk) : chunk.length;
			if (bytes > MAX_BODY_BYTES) {
				req.destroy();
				reject(new Error('Request body too large'));
				return;
			}
			body += chunk;
		});
		req.on('end', () => {
			try { resolve(JSON.parse(body)); }
			catch { reject(new Error('Invalid JSON body')); }
		});
		req.on('error', reject);
	});
}

function jsonResponse(res: ServerResponse, status: number, body: unknown): void {
	const payload = JSON.stringify(body);
	res.writeHead(status, {
		'Content-Type': 'application/json',
		'Content-Length': Buffer.byteLength(payload),
		'Connection': 'close',
	});
	res.end(payload);
}

function validateExecuteRequest(body: unknown): ExecuteRequest {
	if (!body || typeof body !== 'object') throw new Error('Request body must be a JSON object');
	const req = body as Record<string, unknown>;

	if (typeof req.principalId !== 'string' || !req.principalId.trim()) {
		throw new Error('principalId must be a non-empty string');
	}
	if (!TOOL_CLASSES.includes(req.toolClass as never)) {
		throw new Error(`toolClass must be one of: ${TOOL_CLASSES.join(', ')}`);
	}
	if (typeof req.action !== 'string' || !req.action.trim()) {
		throw new Error('action must be a non-empty string');
	}
	if (typeof req.params !== 'object' || req.params === null || Array.isArray(req.params)) {
		throw new Error('params must be a JSON object');
	}
	if (req.taint !== undefined && !Array.isArray(req.taint)) {
		throw new Error('taint must be an array of TaintLabel objects if provided');
	}

	return {
		principalId: req.principalId as string,
		toolClass: req.toolClass as ExecuteRequest['toolClass'],
		action: req.action as string,
		params: req.params as Record<string, unknown>,
		taint: req.taint as import('@arikernel/core').TaintLabel[] | undefined,
	};
}


export async function handleExecute(
	req: IncomingMessage,
	res: ServerResponse,
	registry: PrincipalRegistry,
): Promise<void> {
	let body: unknown;
	try {
		body = await readBody(req);
	} catch (e) {
		const msg = (e as Error).message;
		const status = msg === 'Request body too large' ? 413 : 400;
		return jsonResponse(res, status, { allowed: false, error: msg });
	}

	let execReq: ExecuteRequest;
	try {
		execReq = validateExecuteRequest(body);
	} catch (e) {
		return jsonResponse(res, 400, { allowed: false, error: (e as Error).message });
	}

	const firewall = registry.getOrCreate(execReq.principalId);

	// Request a capability grant before executing — the pipeline requires a
	// valid grantId for protected actions (Step 1.5c enforcement).
	// Always route through firewall.execute() so the pipeline tracks denials
	// in run-state counters (needed for quarantine thresholds).
	// Normalize action to lowercase — CAPABILITY_CLASS_MAP uses lowercase actions
	const normalizedAction = execReq.action.toLowerCase();
	const capClass = deriveCapabilityClass(execReq.toolClass, normalizedAction);
	const grant = firewall.requestCapability(capClass);

	try {
		const result = await firewall.execute({
			toolClass: execReq.toolClass,
			action: normalizedAction,
			parameters: execReq.params,
			taintLabels: execReq.taint,
			grantId: grant.granted ? grant.grant!.id : undefined,
		});

		const response: ExecuteResponse = {
			allowed: result.success,
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
		return jsonResponse(res, 500, { allowed: false, error: (e as Error).message });
	}
}

/**
 * Handle POST /status — returns principal's quarantine state and run counters.
 *
 * This lets untrusted clients introspect their enforcement state without
 * being able to modify it. The sidecar owns the state; clients can only read.
 */
export async function handleStatus(
	req: IncomingMessage,
	res: ServerResponse,
	registry: PrincipalRegistry,
): Promise<void> {
	let body: unknown;
	try {
		body = await readBody(req);
	} catch (e) {
		const msg = (e as Error).message;
		const status = msg === 'Request body too large' ? 413 : 400;
		return jsonResponse(res, status, { error: msg });
	}

	if (!body || typeof body !== 'object') {
		return jsonResponse(res, 400, { error: 'Request body must be a JSON object' });
	}

	const { principalId } = body as Record<string, unknown>;
	if (typeof principalId !== 'string' || !principalId.trim()) {
		return jsonResponse(res, 400, { error: 'principalId must be a non-empty string' });
	}

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
		quarantine: quarantine ? {
			reason: quarantine.reason,
			triggerType: quarantine.triggerType,
			timestamp: quarantine.timestamp,
		} : undefined,
	};

	return jsonResponse(res, 200, response);
}

export function handleHealth(res: ServerResponse): void {
	jsonResponse(res, 200, { status: 'ok', service: 'arikernel-sidecar' });
}

/**
 * Validate Bearer token authentication. Returns true if the request was
 * rejected (caller should return early), false if authentication passed.
 *
 * Uses constant-time comparison to prevent timing attacks.
 */
export function rejectUnauthorized(
	req: IncomingMessage,
	res: ServerResponse,
	expectedToken: string,
): boolean {
	const auth = req.headers.authorization;
	if (!auth || !auth.startsWith('Bearer ')) {
		jsonResponse(res, 401, { error: 'Missing or malformed Authorization header' });
		return true;
	}

	const provided = auth.slice(7);
	if (!timingSafeEqual(provided, expectedToken)) {
		jsonResponse(res, 403, { error: 'Invalid authentication token' });
		return true;
	}

	return false;
}

/** Constant-time string comparison to prevent timing side-channels. */
function timingSafeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) {
		// Compare against b anyway to avoid length-based timing leak
		let result = a.length ^ b.length;
		for (let i = 0; i < a.length; i++) {
			result |= a.charCodeAt(i) ^ (b.charCodeAt(i % b.length) || 0);
		}
		return result === 0; // always false when lengths differ
	}
	let result = 0;
	for (let i = 0; i < a.length; i++) {
		result |= a.charCodeAt(i) ^ b.charCodeAt(i);
	}
	return result === 0;
}
