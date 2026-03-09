import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import type { TaintLabel, ToolCall, ToolResult } from '@arikernel/core';
import { now } from '@arikernel/core';
import type { ToolExecutor } from './base.js';
import { DEFAULT_TIMEOUT_MS, makeResult } from './base.js';

/** Maximum URL length to prevent exfiltration via oversized query strings. */
const MAX_URL_LENGTH = 2048;

/** Maximum number of redirects to follow. */
const MAX_REDIRECTS = 5;

function webTaintLabel(url: string): TaintLabel {
	try {
		const hostname = new URL(url).hostname;
		return { source: 'web', origin: hostname, confidence: 1.0, addedAt: now() };
	} catch {
		return { source: 'web', origin: url, confidence: 1.0, addedAt: now() };
	}
}

/**
 * Check if an IP address is in a private, loopback, or link-local range.
 * Blocks SSRF attempts targeting internal infrastructure.
 */
export function isPrivateIP(ip: string): boolean {
	// IPv4
	if (ip.startsWith('127.')) return true;       // loopback
	if (ip.startsWith('10.')) return true;         // private class A
	if (ip.startsWith('192.168.')) return true;    // private class C
	if (ip.startsWith('169.254.')) return true;    // link-local
	if (ip === '0.0.0.0') return true;             // unspecified
	// 172.16.0.0 – 172.31.255.255
	if (ip.startsWith('172.')) {
		const second = Number.parseInt(ip.split('.')[1], 10);
		if (second >= 16 && second <= 31) return true;
	}

	// IPv6
	const lower = ip.toLowerCase();
	if (lower === '::1') return true;              // loopback
	if (lower === '::') return true;               // unspecified
	if (lower.startsWith('fe80:')) return true;     // link-local
	if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // unique local

	return false;
}

/**
 * Resolve hostname to IP and validate it is not a private/internal address.
 * Throws if the hostname resolves to a blocked range.
 */
export async function validateHostSSRF(hostname: string): Promise<void> {
	// If hostname is already an IP literal, check directly
	if (isIP(hostname)) {
		if (isPrivateIP(hostname)) {
			throw new Error(`SSRF blocked: IP address ${hostname} is in a private/reserved range`);
		}
		return;
	}

	try {
		const { address } = await lookup(hostname);
		if (isPrivateIP(address)) {
			throw new Error(
				`SSRF blocked: hostname '${hostname}' resolves to private IP ${address}`,
			);
		}
	} catch (err) {
		if (err instanceof Error && err.message.startsWith('SSRF blocked')) throw err;
		throw new Error(`DNS resolution failed for '${hostname}': ${err instanceof Error ? err.message : String(err)}`);
	}
}

export class HttpExecutor implements ToolExecutor {
	readonly toolClass = 'http';

	async execute(toolCall: ToolCall): Promise<ToolResult> {
		const start = Date.now();
		const { url, method, headers, body } = toolCall.parameters as {
			url: string;
			method?: string;
			headers?: Record<string, string>;
			body?: unknown;
		};

		// URL length check — prevents data exfiltration via oversized query strings
		if (url.length > MAX_URL_LENGTH) {
			const result = makeResult(toolCall.id, false, start, undefined,
				`URL exceeds maximum length (${MAX_URL_LENGTH} chars). Possible data exfiltration attempt.`);
			return { ...result, taintLabels: [webTaintLabel(url)] };
		}

		const httpMethod = (method ?? toolCall.action).toUpperCase();
		const taintLabels = [webTaintLabel(url)];

		try {
			// SSRF validation — block requests to private/internal networks
			const parsedUrl = new URL(url);
			await validateHostSSRF(parsedUrl.hostname);

			const controller = new AbortController();
			const timeout = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);

			// Manual redirect handling to validate each hop
			let currentUrl = url;
			let response: Response;
			let redirectCount = 0;

			// biome-ignore lint/suspicious/noAssignInExpressions: redirect loop pattern
			while (true) {
				response = await fetch(currentUrl, {
					method: httpMethod,
					headers: headers ?? undefined,
					body: body ? JSON.stringify(body) : undefined,
					signal: controller.signal,
					redirect: 'manual', // Handle redirects ourselves
				});

				// Check for redirects
				if (response.status >= 300 && response.status < 400) {
					const location = response.headers.get('location');
					if (!location) break;

					redirectCount++;
					if (redirectCount > MAX_REDIRECTS) {
						clearTimeout(timeout);
						const result = makeResult(toolCall.id, false, start, undefined,
							`Too many redirects (>${MAX_REDIRECTS}). Possible redirect loop.`);
						return { ...result, taintLabels };
					}

					// Resolve relative redirects against current URL
					const redirectUrl = new URL(location, currentUrl);

					// Validate redirect destination is not a private IP (SSRF via redirect)
					await validateHostSSRF(redirectUrl.hostname);

					currentUrl = redirectUrl.href;
					continue;
				}

				break;
			}

			clearTimeout(timeout);

			const contentType = response.headers.get('content-type') ?? '';
			const responseData = contentType.includes('application/json')
				? await response.json()
				: await response.text();

			const result = makeResult(toolCall.id, response.ok, start, {
				status: response.status,
				headers: Object.fromEntries(response.headers.entries()),
				body: responseData,
			});

			return { ...result, taintLabels };
		} catch (err) {
			const error = err instanceof Error ? err.message : String(err);
			const result = makeResult(toolCall.id, false, start, undefined, error);
			return { ...result, taintLabels };
		}
	}
}
