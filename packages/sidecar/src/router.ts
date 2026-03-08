import type { IncomingMessage, ServerResponse } from 'node:http';
import type { PrincipalRegistry } from './registry.js';
import type { ExecuteRequest, ExecuteResponse } from './types.js';
import { TOOL_CLASSES, ToolCallDeniedError, ApprovalRequiredError } from '@arikernel/core';

async function readBody(req: IncomingMessage): Promise<unknown> {
	return new Promise((resolve, reject) => {
		let body = '';
		req.on('data', (chunk) => { body += chunk; });
		req.on('end', () => {
			try { resolve(JSON.parse(body)); }
			catch { reject(new Error('Invalid JSON body')); }
		});
		req.on('error', reject);
	});
}

function jsonResponse(res: ServerResponse, status: number, body: unknown): void {
	const payload = JSON.stringify(body);
	res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) });
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
	} catch {
		return jsonResponse(res, 400, { allowed: false, error: 'Invalid JSON body' });
	}

	let execReq: ExecuteRequest;
	try {
		execReq = validateExecuteRequest(body);
	} catch (e) {
		return jsonResponse(res, 400, { allowed: false, error: (e as Error).message });
	}

	const firewall = registry.getOrCreate(execReq.principalId);

	try {
		const result = await firewall.execute({
			toolClass: execReq.toolClass,
			action: execReq.action,
			parameters: execReq.params,
			taintLabels: execReq.taint,
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

export function handleHealth(res: ServerResponse): void {
	jsonResponse(res, 200, { status: 'ok', service: 'arikernel-sidecar' });
}
