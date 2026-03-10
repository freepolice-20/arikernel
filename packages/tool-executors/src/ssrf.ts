/**
 * SSRF protection: DNS resolution, IP validation, and request pinning.
 *
 * Defends against:
 *  - Direct private-IP access (127.x, 10.x, 172.16-31.x, 192.168.x, 169.254.x, etc.)
 *  - DNS rebinding (TOCTOU) — resolved IP is returned for connection pinning
 *  - Redirect-based SSRF — each hop is re-resolved and re-validated
 */
import { lookup } from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import { isIP } from "node:net";

/** Check if an IP address is in a private, loopback, or link-local range. */
export function isPrivateIP(ip: string): boolean {
	// IPv4
	if (ip.startsWith("127.")) return true;
	if (ip.startsWith("10.")) return true;
	if (ip.startsWith("192.168.")) return true;
	if (ip.startsWith("169.254.")) return true;
	if (ip === "0.0.0.0") return true;
	if (ip.startsWith("172.")) {
		const second = Number.parseInt(ip.split(".")[1], 10);
		if (second >= 16 && second <= 31) return true;
	}

	// IPv6
	const lower = ip.toLowerCase();
	if (lower === "::1") return true;
	if (lower === "::") return true;
	if (lower.startsWith("fe80:")) return true;
	if (lower.startsWith("fc") || lower.startsWith("fd")) return true;

	return false;
}

/**
 * Resolve hostname to an IP address and validate it is not private/reserved.
 * Returns the resolved IP so callers can pin the connection to it.
 */
export async function resolveHost(hostname: string): Promise<string> {
	if (isIP(hostname)) {
		if (isPrivateIP(hostname)) {
			throw new Error(`SSRF blocked: IP address ${hostname} is in a private/reserved range`);
		}
		return hostname;
	}

	try {
		const { address } = await lookup(hostname);
		if (isPrivateIP(address)) {
			throw new Error(
				`SSRF blocked: hostname '${hostname}' resolves to private IP ${address}`,
			);
		}
		return address;
	} catch (err) {
		if (err instanceof Error && err.message.startsWith("SSRF blocked")) throw err;
		throw new Error(
			`DNS resolution failed for '${hostname}': ${err instanceof Error ? err.message : String(err)}`,
		);
	}
}

/** Backward-compatible alias — validates but discards the resolved IP. */
export async function validateHostSSRF(hostname: string): Promise<void> {
	await resolveHost(hostname);
}

export interface PinnedResponse {
	status: number;
	headers: Record<string, string>;
	body: string;
	redirectChain: string[];
}

/**
 * Execute an HTTP request pinned to a pre-resolved IP address.
 * Uses node:http/node:https directly to eliminate the TOCTOU DNS rebinding window.
 */
export function pinnedRequest(
	resolvedIP: string,
	parsed: URL,
	method: string,
	headers: Record<string, string>,
	body: string | undefined,
	timeoutMs: number,
): Promise<{ status: number; headers: Record<string, string>; body: string; location?: string }> {
	return new Promise((resolve, reject) => {
		const isHttps = parsed.protocol === "https:";
		const mod = isHttps ? https : http;

		const options: http.RequestOptions = {
			hostname: resolvedIP,
			port: parsed.port || (isHttps ? 443 : 80),
			path: parsed.pathname + parsed.search,
			method,
			headers: { ...headers, host: parsed.host },
			timeout: timeoutMs,
			...(isHttps ? { servername: parsed.hostname } : {}),
		};

		const req = mod.request(options, (res) => {
			const chunks: Buffer[] = [];
			res.on("data", (chunk: Buffer) => chunks.push(chunk));
			res.on("end", () => {
				const responseBody = Buffer.concat(chunks).toString("utf-8");
				const responseHeaders: Record<string, string> = {};
				for (const [key, value] of Object.entries(res.headers)) {
					if (value != null) {
						responseHeaders[key] = Array.isArray(value) ? value.join(", ") : value;
					}
				}
				resolve({
					status: res.statusCode ?? 0,
					headers: responseHeaders,
					body: responseBody,
					location: res.headers.location ?? undefined,
				});
			});
		});

		req.on("error", reject);
		req.on("timeout", () => {
			req.destroy();
			reject(new Error("Request timed out"));
		});

		if (body) req.write(body);
		req.end();
	});
}

/**
 * Full SSRF-safe request with redirect following.
 * At each hop: re-resolves DNS, validates IP, pins connection, blocks cross-host redirects.
 */
export type HostResolver = (hostname: string) => Promise<string>;

export async function ssrfSafeRequest(
	url: string,
	method: string,
	headers: Record<string, string>,
	body: string | undefined,
	timeoutMs: number,
	maxRedirects: number,
	resolver: HostResolver = resolveHost,
): Promise<PinnedResponse> {
	let currentUrl = url;
	const redirectChain: string[] = [];
	const originalHost = new URL(url).hostname;

	for (let hop = 0; ; hop++) {
		const parsed = new URL(currentUrl);
		const resolvedIP = await resolver(parsed.hostname);

		const res = await pinnedRequest(resolvedIP, parsed, method, headers, body, timeoutMs);

		if (res.status >= 300 && res.status < 400 && res.location) {
			if (hop >= maxRedirects) {
				throw new Error(`Too many redirects (>${maxRedirects}). Possible redirect loop.`);
			}

			const redirectUrl = new URL(res.location, currentUrl);

			// Block cross-host redirects — prevents redirect-based SSRF to internal services
			if (redirectUrl.hostname !== originalHost) {
				throw new Error(
					`SSRF blocked: redirect changed host from '${originalHost}' to '${redirectUrl.hostname}'`,
				);
			}

			redirectChain.push(currentUrl);
			currentUrl = redirectUrl.href;

			// Subsequent redirect hops use GET per HTTP spec (PRG pattern)
			method = "GET";
			body = undefined;
			continue;
		}

		return { status: res.status, headers: res.headers, body: res.body, redirectChain };
	}
}
