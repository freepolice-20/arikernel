import http from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { isPrivateIP, resolveHost, ssrfSafeRequest } from "../src/ssrf.js";
import type { HostResolver } from "../src/ssrf.js";

// ---------------------------------------------------------------------------
// isPrivateIP — unit tests (no network)
// ---------------------------------------------------------------------------

describe("isPrivateIP", () => {
	// IPv4 loopback
	it("blocks 127.0.0.1 (loopback)", () => {
		expect(isPrivateIP("127.0.0.1")).toBe(true);
	});

	it("blocks 127.0.0.2 (loopback range)", () => {
		expect(isPrivateIP("127.0.0.2")).toBe(true);
	});

	// IPv4 private ranges
	it("blocks 10.0.0.1 (class A private)", () => {
		expect(isPrivateIP("10.0.0.1")).toBe(true);
	});

	it("blocks 10.255.255.255", () => {
		expect(isPrivateIP("10.255.255.255")).toBe(true);
	});

	it("blocks 192.168.1.1 (class C private)", () => {
		expect(isPrivateIP("192.168.1.1")).toBe(true);
	});

	it("blocks 172.16.0.1 (class B private)", () => {
		expect(isPrivateIP("172.16.0.1")).toBe(true);
	});

	it("blocks 172.31.255.255 (class B upper bound)", () => {
		expect(isPrivateIP("172.31.255.255")).toBe(true);
	});

	it("allows 172.32.0.1 (outside private range)", () => {
		expect(isPrivateIP("172.32.0.1")).toBe(false);
	});

	it("allows 172.15.0.1 (outside private range)", () => {
		expect(isPrivateIP("172.15.0.1")).toBe(false);
	});

	// Link-local
	it("blocks 169.254.1.1 (link-local)", () => {
		expect(isPrivateIP("169.254.1.1")).toBe(true);
	});

	// Unspecified
	it("blocks 0.0.0.0 (unspecified)", () => {
		expect(isPrivateIP("0.0.0.0")).toBe(true);
	});

	// Public IPs
	it("allows 8.8.8.8 (public)", () => {
		expect(isPrivateIP("8.8.8.8")).toBe(false);
	});

	it("allows 1.1.1.1 (public)", () => {
		expect(isPrivateIP("1.1.1.1")).toBe(false);
	});

	it("allows 93.184.216.34 (public)", () => {
		expect(isPrivateIP("93.184.216.34")).toBe(false);
	});

	// IPv6
	it("blocks ::1 (IPv6 loopback)", () => {
		expect(isPrivateIP("::1")).toBe(true);
	});

	it("blocks :: (IPv6 unspecified)", () => {
		expect(isPrivateIP("::")).toBe(true);
	});

	it("blocks fe80::1 (IPv6 link-local)", () => {
		expect(isPrivateIP("fe80::1")).toBe(true);
	});

	it("blocks fc00::1 (IPv6 unique local)", () => {
		expect(isPrivateIP("fc00::1")).toBe(true);
	});

	it("blocks fd00::1 (IPv6 unique local)", () => {
		expect(isPrivateIP("fd00::1")).toBe(true);
	});

	it("allows 2001:db8::1 (public IPv6)", () => {
		expect(isPrivateIP("2001:db8::1")).toBe(false);
	});

	// --- IPv4-mapped IPv6 bypass vectors ---
	it("blocks ::ffff:127.0.0.1 (IPv4-mapped loopback)", () => {
		expect(isPrivateIP("::ffff:127.0.0.1")).toBe(true);
	});

	it("blocks ::ffff:10.0.0.1 (IPv4-mapped RFC1918 class A)", () => {
		expect(isPrivateIP("::ffff:10.0.0.1")).toBe(true);
	});

	it("blocks ::ffff:192.168.1.10 (IPv4-mapped RFC1918 class C)", () => {
		expect(isPrivateIP("::ffff:192.168.1.10")).toBe(true);
	});

	it("blocks ::ffff:172.16.0.1 (IPv4-mapped RFC1918 class B)", () => {
		expect(isPrivateIP("::ffff:172.16.0.1")).toBe(true);
	});

	it("blocks ::ffff:169.254.169.254 (IPv4-mapped cloud metadata)", () => {
		expect(isPrivateIP("::ffff:169.254.169.254")).toBe(true);
	});

	it("blocks ::ffff:0.0.0.0 (IPv4-mapped unspecified)", () => {
		expect(isPrivateIP("::ffff:0.0.0.0")).toBe(true);
	});

	it("allows ::ffff:8.8.8.8 (IPv4-mapped public)", () => {
		expect(isPrivateIP("::ffff:8.8.8.8")).toBe(false);
	});

	it("allows ::ffff:93.184.216.34 (IPv4-mapped public)", () => {
		expect(isPrivateIP("::ffff:93.184.216.34")).toBe(false);
	});

	// --- Additional IPv6 reserved ranges ---
	it("blocks ff02::1 (IPv6 multicast)", () => {
		expect(isPrivateIP("ff02::1")).toBe(true);
	});

	it("blocks 255.255.255.255 (IPv4 broadcast)", () => {
		expect(isPrivateIP("255.255.255.255")).toBe(true);
	});

	// --- Case insensitivity ---
	it("blocks ::FFFF:127.0.0.1 (uppercase mapped prefix)", () => {
		expect(isPrivateIP("::FFFF:127.0.0.1")).toBe(true);
	});

	// --- Fail-closed on garbage input ---
	it("blocks garbage input (fail-closed)", () => {
		expect(isPrivateIP("not-an-ip")).toBe(true);
	});

	// --- Public IPv6 that must still pass ---
	it("allows 2607:f8b0:4004:800::200e (public IPv6)", () => {
		expect(isPrivateIP("2607:f8b0:4004:800::200e")).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// resolveHost — DNS resolution + validation
// ---------------------------------------------------------------------------

describe("resolveHost", () => {
	it("blocks IP literal in private range", async () => {
		await expect(resolveHost("127.0.0.1")).rejects.toThrow("SSRF blocked");
		await expect(resolveHost("10.0.0.1")).rejects.toThrow("SSRF blocked");
		await expect(resolveHost("192.168.1.1")).rejects.toThrow("SSRF blocked");
		await expect(resolveHost("169.254.169.254")).rejects.toThrow("SSRF blocked");
	});

	it("returns the IP unchanged for public IP literals", async () => {
		const ip = await resolveHost("8.8.8.8");
		expect(ip).toBe("8.8.8.8");
	});

	it("blocks IPv4-mapped IPv6 private literals", async () => {
		await expect(resolveHost("::ffff:127.0.0.1")).rejects.toThrow("SSRF blocked");
		await expect(resolveHost("::ffff:10.0.0.1")).rejects.toThrow("SSRF blocked");
		await expect(resolveHost("::ffff:192.168.1.10")).rejects.toThrow("SSRF blocked");
		await expect(resolveHost("::ffff:169.254.169.254")).rejects.toThrow("SSRF blocked");
	});

	it("blocks IPv6 loopback and link-local literals", async () => {
		await expect(resolveHost("::1")).rejects.toThrow("SSRF blocked");
		await expect(resolveHost("fe80::1")).rejects.toThrow("SSRF blocked");
	});
});

// ---------------------------------------------------------------------------
// ssrfSafeRequest — integration tests with a local HTTP server
// ---------------------------------------------------------------------------

describe("ssrfSafeRequest", () => {
	let server: http.Server;
	let port: number;

	beforeAll(
		() =>
			new Promise<void>((resolve) => {
				server = http.createServer((req, res) => {
					const url = new URL(req.url ?? "/", "http://localhost");

					if (url.pathname === "/ok") {
						res.writeHead(200, { "content-type": "application/json" });
						res.end(JSON.stringify({ status: "ok" }));
					} else if (url.pathname === "/redirect-same-host") {
						res.writeHead(302, { location: "/ok" });
						res.end();
					} else if (url.pathname === "/redirect-cross-host") {
						res.writeHead(302, { location: "http://internal.corp:9999/secret" });
						res.end();
					} else if (url.pathname === "/redirect-private") {
						res.writeHead(302, { location: "http://169.254.169.254/metadata" });
						res.end();
					} else if (url.pathname === "/redirect-loop") {
						res.writeHead(302, { location: "/redirect-loop" });
						res.end();
					} else {
						res.writeHead(404);
						res.end("not found");
					}
				});

				server.listen(0, "127.0.0.1", () => {
					port = (server.address() as { port: number }).port;
					resolve();
				});
			}),
	);

	afterAll(
		() =>
			new Promise<void>((resolve) => {
				server.close(() => resolve());
			}),
	);

	/** Test resolver that allows localhost for our test server. */
	const testResolver: HostResolver = async (hostname: string) => {
		if (hostname === "localhost" || hostname === "127.0.0.1") return "127.0.0.1";
		// Apply real SSRF validation for everything else
		return resolveHost(hostname);
	};

	it("completes a normal request", async () => {
		const res = await ssrfSafeRequest(
			`http://localhost:${port}/ok`,
			"GET",
			{},
			undefined,
			5000,
			5,
			testResolver,
		);
		expect(res.status).toBe(200);
		expect(res.body).toContain('"ok"');
	});

	it("follows same-host redirects", async () => {
		const res = await ssrfSafeRequest(
			`http://localhost:${port}/redirect-same-host`,
			"GET",
			{},
			undefined,
			5000,
			5,
			testResolver,
		);
		expect(res.status).toBe(200);
		expect(res.redirectChain.length).toBe(1);
	});

	it("blocks cross-host redirects", async () => {
		await expect(
			ssrfSafeRequest(
				`http://localhost:${port}/redirect-cross-host`,
				"GET",
				{},
				undefined,
				5000,
				5,
				testResolver,
			),
		).rejects.toThrow("SSRF blocked: redirect changed host");
	});

	it("blocks redirect to cloud metadata (169.254.169.254)", async () => {
		await expect(
			ssrfSafeRequest(
				`http://localhost:${port}/redirect-private`,
				"GET",
				{},
				undefined,
				5000,
				5,
				testResolver,
			),
		).rejects.toThrow("SSRF blocked");
	});

	it("stops after max redirects", async () => {
		await expect(
			ssrfSafeRequest(
				`http://localhost:${port}/redirect-loop`,
				"GET",
				{},
				undefined,
				5000,
				2,
				testResolver,
			),
		).rejects.toThrow("Too many redirects");
	});

	it("blocks direct requests to private IPs (no resolver override)", async () => {
		await expect(
			ssrfSafeRequest("http://127.0.0.1/secret", "GET", {}, undefined, 5000, 5),
		).rejects.toThrow("SSRF blocked");

		await expect(
			ssrfSafeRequest("http://169.254.169.254/metadata", "GET", {}, undefined, 5000, 5),
		).rejects.toThrow("SSRF blocked");

		await expect(
			ssrfSafeRequest("http://10.0.0.1/internal", "GET", {}, undefined, 5000, 5),
		).rejects.toThrow("SSRF blocked");
	});

	it("blocks DNS rebinding where hostname resolves to private IP", async () => {
		const rebindResolver: HostResolver = async () => {
			throw new Error(
				"SSRF blocked: hostname 'evil-rebind.test' resolves to private IP 192.168.1.1",
			);
		};

		await expect(
			ssrfSafeRequest(
				"http://evil-rebind.test/steal",
				"GET",
				{},
				undefined,
				5000,
				5,
				rebindResolver,
			),
		).rejects.toThrow("SSRF blocked");
	});

	it("pins request to resolved IP (TOCTOU protection)", async () => {
		let resolveCount = 0;
		const trackingResolver: HostResolver = async (hostname: string) => {
			resolveCount++;
			if (hostname === "localhost") return "127.0.0.1";
			throw new Error(`SSRF blocked: unexpected host ${hostname}`);
		};

		const res = await ssrfSafeRequest(
			`http://localhost:${port}/ok`,
			"GET",
			{},
			undefined,
			5000,
			5,
			trackingResolver,
		);

		expect(res.status).toBe(200);
		// Resolver was called exactly once (no second resolution by fetch)
		expect(resolveCount).toBe(1);
	});

	it("re-resolves DNS on each redirect hop", async () => {
		const resolved: string[] = [];
		const hoppingResolver: HostResolver = async (hostname: string) => {
			resolved.push(hostname);
			if (hostname === "localhost") return "127.0.0.1";
			throw new Error(`SSRF blocked: unexpected host ${hostname}`);
		};

		const res = await ssrfSafeRequest(
			`http://localhost:${port}/redirect-same-host`,
			"GET",
			{},
			undefined,
			5000,
			5,
			hoppingResolver,
		);

		expect(res.status).toBe(200);
		// Resolved once for initial request, once for redirect target
		expect(resolved).toEqual(["localhost", "localhost"]);
	});
});
