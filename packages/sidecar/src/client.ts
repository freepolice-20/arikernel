import type { TaintLabel } from '@arikernel/core';
import type { ExecuteRequest, ExecuteResponse } from './types.js';

export interface SidecarClientOptions {
	/** Base URL of the sidecar server. Default: http://localhost:8787 */
	baseUrl?: string;
	/** principalId to use for all calls from this client instance */
	principalId: string;
}

/**
 * Thin HTTP client for the AriKernel sidecar.
 * Agents use this instead of calling tools directly — the sidecar enforces policy.
 */
export class SidecarClient {
	private readonly baseUrl: string;
	private readonly principalId: string;

	constructor(options: SidecarClientOptions) {
		this.baseUrl = (options.baseUrl ?? 'http://localhost:8787').replace(/\/$/, '');
		this.principalId = options.principalId;
	}

	async execute(
		toolClass: ExecuteRequest['toolClass'],
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
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(body),
		});

		return res.json() as Promise<ExecuteResponse>;
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
