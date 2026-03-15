import type { TaintLabel, ToolCall, ToolResult } from "@arikernel/core";
import { now } from "@arikernel/core";
import type { ToolExecutor } from "./base.js";
import { DEFAULT_TIMEOUT_MS, makeResult } from "./base.js";
import { ssrfSafeRequest } from "./ssrf.js";

// Re-export SSRF utilities for backward compatibility
export { isPrivateIP, resolveHost, validateHostSSRF } from "./ssrf.js";

/** Maximum URL length to prevent exfiltration via oversized query strings. */
const MAX_URL_LENGTH = 2048;

/** Maximum number of redirects to follow. */
const MAX_REDIRECTS = 5;

/** HTTP methods that must not carry a request body (RFC 9110 §9.3.1, §9.3.2). */
const BODYLESS_METHODS = new Set(["GET", "HEAD"]);

/**
 * Headers safe to send on GET/HEAD requests in any context.
 * Non-standard or custom headers (X-*, etc.) are potential exfil vectors
 * and are stripped when the run is in a security-sensitive state.
 */
export const SAFE_GET_HEADERS = new Set(["accept", "accept-encoding", "accept-language", "host"]);

/**
 * Headers allowed on GET/HEAD but whose values must be inspected for encoded
 * payloads in security-sensitive contexts (post-sensitive-read).
 * These headers legitimately appear on requests but can carry arbitrary data.
 */
export const VALUE_INSPECTED_HEADERS = new Set([
	"cache-control",
	"connection",
	"cookie",
	"if-match",
	"if-modified-since",
	"if-none-match",
	"if-range",
	"if-unmodified-since",
	"range",
	"referer",
	"te",
	"user-agent",
]);

/** Canonical mapping from tool action to HTTP method. */
const ACTION_TO_METHOD: Record<string, string> = {
	get: "GET",
	post: "POST",
	put: "PUT",
	patch: "PATCH",
	delete: "DELETE",
	head: "HEAD",
	options: "OPTIONS",
};

function webTaintLabel(url: string): TaintLabel {
	try {
		const hostname = new URL(url).hostname;
		return { source: "web", origin: hostname, confidence: 1.0, addedAt: now() };
	} catch {
		return { source: "web", origin: url, confidence: 1.0, addedAt: now() };
	}
}

export class HttpExecutor implements ToolExecutor {
	readonly toolClass = "http";

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
			const result = makeResult(
				toolCall.id,
				false,
				start,
				undefined,
				`URL exceeds maximum length (${MAX_URL_LENGTH} chars). Possible data exfiltration attempt.`,
			);
			return { ...result, taintLabels: [webTaintLabel(url)] };
		}

		// Derive HTTP method exclusively from the tool action — single source of truth.
		// Reject params.method if it conflicts, preventing policy bypass via
		// action="get" + params.method="POST".
		const canonicalMethod = ACTION_TO_METHOD[toolCall.action.toLowerCase()];
		if (!canonicalMethod) {
			const result = makeResult(
				toolCall.id,
				false,
				start,
				undefined,
				`Unknown HTTP action '${toolCall.action}'. Allowed: ${Object.keys(ACTION_TO_METHOD).join(", ")}`,
			);
			return { ...result, taintLabels: [webTaintLabel(url)] };
		}

		if (method !== undefined) {
			const normalized = method.toUpperCase();
			if (normalized !== canonicalMethod) {
				const result = makeResult(
					toolCall.id,
					false,
					start,
					undefined,
					`HTTP method mismatch: action '${toolCall.action}' requires ${canonicalMethod} but params.method='${method}'. The HTTP method is derived from the tool action to prevent policy bypass.`,
				);
				return { ...result, taintLabels: [webTaintLabel(url)] };
			}
		}

		const httpMethod = canonicalMethod;
		const taintLabels = [webTaintLabel(url)];

		// GET and HEAD must not carry a request body (RFC 9110 §9.3.1, §9.3.2).
		// A body on these methods is a semantic violation and a potential exfil vector —
		// secrets could be smuggled in a JSON body that bypasses query-string checks.
		if (BODYLESS_METHODS.has(httpMethod) && body !== undefined && body !== null) {
			const result = makeResult(
				toolCall.id,
				false,
				start,
				undefined,
				`HTTP ${httpMethod} must not carry a request body. Bodies on GET/HEAD are a potential data exfiltration vector.`,
			);
			return { ...result, taintLabels };
		}

		try {
			const response = await ssrfSafeRequest(
				url,
				httpMethod,
				headers ?? {},
				body ? JSON.stringify(body) : undefined,
				DEFAULT_TIMEOUT_MS,
				MAX_REDIRECTS,
			);

			const contentType = response.headers["content-type"] ?? "";
			let responseData: unknown = response.body;
			if (contentType.includes("application/json")) {
				try {
					responseData = JSON.parse(response.body);
				} catch {
					/* keep raw body */
				}
			}

			const result = makeResult(
				toolCall.id,
				response.status >= 200 && response.status < 300,
				start,
				{
					status: response.status,
					headers: response.headers,
					body: responseData,
				},
			);

			return { ...result, taintLabels };
		} catch (err) {
			const error = err instanceof Error ? err.message : String(err);
			const result = makeResult(toolCall.id, false, start, undefined, error);
			return { ...result, taintLabels };
		}
	}
}
