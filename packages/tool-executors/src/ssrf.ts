/**
 * SSRF protection: DNS resolution, IP validation, and request pinning.
 *
 * Defends against:
 *  - Direct private-IP access (127.x, 10.x, 172.16-31.x, 192.168.x, 169.254.x, etc.)
 *  - IPv4-mapped IPv6 bypass (::ffff:127.0.0.1, ::ffff:10.0.0.1, etc.)
 *  - IPv6 loopback/link-local/ULA/multicast (::1, fe80::, fc/fd, ff00::)
 *  - DNS rebinding (TOCTOU) — resolved IP is returned for connection pinning
 *  - Redirect-based SSRF — each hop is re-resolved and re-validated
 */
import { lookup } from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import { isIP } from "node:net";

/**
 * Normalize an IP string to a canonical form and, for IPv4-mapped IPv6
 * addresses (::ffff:x.x.x.x), extract the inner IPv4 address so that
 * private-range checks cannot be bypassed with alternate encodings.
 *
 * Returns { version: 4 | 6, canonical: string }.
 * Throws on unparseable input (fail-closed).
 */
function normalizeIP(ip: string): { version: 4 | 6; canonical: string } {
	const raw = ip.trim();
	const kind = isIP(raw); // 0 = invalid, 4 = IPv4, 6 = IPv6

	if (kind === 4) return { version: 4, canonical: raw };

	if (kind === 6) {
		const lower = raw.toLowerCase();
		// IPv4-mapped IPv6  —  ::ffff:a.b.c.d
		const mapped = lower.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
		if (mapped) {
			return { version: 4, canonical: mapped[1] };
		}
		return { version: 6, canonical: lower };
	}

	// kind === 0 — not a valid IP; fail closed
	throw new Error(`SSRF blocked: "${raw}" is not a valid IP address`);
}

/** Check whether an IPv4 address is private/reserved. */
function isPrivateIPv4(ip: string): boolean {
	if (ip.startsWith("127.")) return true; // loopback
	if (ip.startsWith("10.")) return true; // RFC 1918
	if (ip.startsWith("192.168.")) return true; // RFC 1918
	if (ip.startsWith("169.254.")) return true; // link-local
	if (ip === "0.0.0.0") return true; // unspecified
	if (ip === "255.255.255.255") return true; // broadcast
	if (ip.startsWith("172.")) {
		const second = Number.parseInt(ip.split(".")[1], 10);
		if (second >= 16 && second <= 31) return true; // RFC 1918
	}
	return false;
}

/** Check whether an IPv6 address (already lowercased) is private/reserved. */
function isPrivateIPv6(ip: string): boolean {
	if (ip === "::1") return true; // loopback
	if (ip === "::") return true; // unspecified
	if (ip.startsWith("fe80")) return true; // link-local  (fe80::/10)
	if (ip.startsWith("fc") || ip.startsWith("fd")) return true; // ULA (fc00::/7)
	if (ip.startsWith("ff")) return true; // multicast (ff00::/8)
	return false;
}

/**
 * Check if an IP address is in a private, loopback, link-local, multicast,
 * or otherwise reserved range.
 *
 * Handles IPv4-mapped IPv6 (::ffff:x.x.x.x) by extracting the inner IPv4
 * address and checking it against IPv4 ranges.  Fail-closed: unparseable
 * addresses are treated as private.
 */
export function isPrivateIP(ip: string): boolean {
	let norm: { version: 4 | 6; canonical: string };
	try {
		norm = normalizeIP(ip);
	} catch {
		return true; // fail closed — unparseable ⇒ blocked
	}

	if (norm.version === 4) return isPrivateIPv4(norm.canonical);
	return isPrivateIPv6(norm.canonical);
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
			throw new Error(`SSRF blocked: hostname '${hostname}' resolves to private IP ${address}`);
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

		const MAX_RESPONSE_BYTES = 10 * 1024 * 1024; // 10 MB

		const req = mod.request(options, (res) => {
			const chunks: Buffer[] = [];
			let totalBytes = 0;
			res.on("data", (chunk: Buffer) => {
				totalBytes += chunk.length;
				if (totalBytes > MAX_RESPONSE_BYTES) {
					res.destroy();
					reject(new Error(`Response body exceeds ${MAX_RESPONSE_BYTES} bytes limit`));
					return;
				}
				chunks.push(chunk);
			});
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
	let currentMethod = method;
	let currentBody = body;
	const redirectChain: string[] = [];
	const originalHost = new URL(url).hostname;

	for (let hop = 0; ; hop++) {
		const parsed = new URL(currentUrl);
		const resolvedIP = await resolver(parsed.hostname);

		const res = await pinnedRequest(
			resolvedIP,
			parsed,
			currentMethod,
			headers,
			currentBody,
			timeoutMs,
		);

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
			currentMethod = "GET";
			currentBody = undefined;
			continue;
		}

		return { status: res.status, headers: res.headers, body: res.body, redirectChain };
	}
}
