/**
 * Regression tests: IPv4-mapped IPv6 SSRF bypass vectors.
 *
 * These tests lock in correct handling of IPv4-mapped IPv6 addresses
 * that could bypass SSRF protections if the normalization layer is
 * removed or weakened. Each case represents a known bypass technique
 * from external security review findings.
 */
import { describe, expect, it } from "vitest";
import { isPrivateIP, resolveHost } from "../src/ssrf.js";

// ---------------------------------------------------------------------------
// Additional IPv4-mapped IPv6 bypass vectors not in the main test suite
// ---------------------------------------------------------------------------

describe("SSRF regression: IPv4-mapped IPv6 bypass edge cases", () => {
	// ── Mixed case and whitespace normalization ───────────────────────
	it("blocks ::FfFf:127.0.0.1 (mixed case mapped prefix)", () => {
		expect(isPrivateIP("::FfFf:127.0.0.1")).toBe(true);
	});

	it("blocks ::ffff:127.0.0.1 with leading/trailing whitespace", () => {
		expect(isPrivateIP("  ::ffff:127.0.0.1  ")).toBe(true);
	});

	// ── Cloud metadata endpoint — the highest-value SSRF target ──────
	it("blocks ::ffff:169.254.169.254 (AWS/GCP metadata via mapped IPv6)", () => {
		expect(isPrivateIP("::ffff:169.254.169.254")).toBe(true);
	});

	it("blocks ::FFFF:169.254.169.254 (uppercase mapped metadata)", () => {
		expect(isPrivateIP("::FFFF:169.254.169.254")).toBe(true);
	});

	// ── RFC 1918 boundary conditions via mapped IPv6 ─────────────────
	it("blocks ::ffff:172.16.0.0 (class B lower bound via mapped)", () => {
		expect(isPrivateIP("::ffff:172.16.0.0")).toBe(true);
	});

	it("blocks ::ffff:172.31.255.255 (class B upper bound via mapped)", () => {
		expect(isPrivateIP("::ffff:172.31.255.255")).toBe(true);
	});

	it("allows ::ffff:172.32.0.0 (just outside class B via mapped)", () => {
		expect(isPrivateIP("::ffff:172.32.0.0")).toBe(false);
	});

	it("allows ::ffff:172.15.255.255 (just below class B via mapped)", () => {
		expect(isPrivateIP("::ffff:172.15.255.255")).toBe(false);
	});

	it("blocks ::ffff:10.255.255.255 (class A upper bound via mapped)", () => {
		expect(isPrivateIP("::ffff:10.255.255.255")).toBe(true);
	});

	it("blocks ::ffff:192.168.255.255 (class C upper bound via mapped)", () => {
		expect(isPrivateIP("::ffff:192.168.255.255")).toBe(true);
	});

	// ── Broadcast/unspecified via mapped ──────────────────────────────
	it("blocks ::ffff:255.255.255.255 (broadcast via mapped)", () => {
		expect(isPrivateIP("::ffff:255.255.255.255")).toBe(true);
	});

	// ── Public IPs via mapped — must NOT be blocked ──────────────────
	it("allows ::ffff:1.1.1.1 (Cloudflare DNS via mapped)", () => {
		expect(isPrivateIP("::ffff:1.1.1.1")).toBe(false);
	});

	it("allows ::ffff:104.16.0.1 (Cloudflare via mapped)", () => {
		expect(isPrivateIP("::ffff:104.16.0.1")).toBe(false);
	});

	// ── Fail-closed: garbage that looks like mapped IPv6 ─────────────
	it("blocks ::ffff:999.999.999.999 (invalid octets, fail-closed)", () => {
		// node:net isIP() returns 0 for invalid octets → fail-closed
		expect(isPrivateIP("::ffff:999.999.999.999")).toBe(true);
	});

	it("blocks empty string (fail-closed)", () => {
		expect(isPrivateIP("")).toBe(true);
	});

	it("blocks null-byte injection attempt (fail-closed)", () => {
		expect(isPrivateIP("::ffff:127.0.0.1\x00evil.com")).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// resolveHost: IPv4-mapped IPv6 bypass via host literals
// ---------------------------------------------------------------------------

describe("SSRF regression: resolveHost blocks mapped IPv6 literals", () => {
	it("blocks ::ffff:172.16.0.1 literal", async () => {
		await expect(resolveHost("::ffff:172.16.0.1")).rejects.toThrow("SSRF blocked");
	});

	it("blocks ::ffff:172.31.255.255 literal", async () => {
		await expect(resolveHost("::ffff:172.31.255.255")).rejects.toThrow("SSRF blocked");
	});

	it("blocks ::ffff:0.0.0.0 literal", async () => {
		await expect(resolveHost("::ffff:0.0.0.0")).rejects.toThrow("SSRF blocked");
	});

	it("allows ::ffff:8.8.4.4 (public Google DNS via mapped literal)", async () => {
		const ip = await resolveHost("::ffff:8.8.4.4");
		// resolveHost returns the IP unchanged for valid public IP literals
		expect(ip).toBe("::ffff:8.8.4.4");
	});
});

// ---------------------------------------------------------------------------
// IPv4-mapped IPv6 hex form: ::ffff:HHHH:HHHH
// ---------------------------------------------------------------------------

describe("SSRF regression: IPv4-mapped IPv6 hex form bypass", () => {
	it("blocks ::ffff:7f00:1 (127.0.0.1 in hex form)", () => {
		expect(isPrivateIP("::ffff:7f00:1")).toBe(true);
	});

	it("blocks ::ffff:7f00:0001 (127.0.0.1 zero-padded hex)", () => {
		expect(isPrivateIP("::ffff:7f00:0001")).toBe(true);
	});

	it("blocks ::ffff:0a00:0001 (10.0.0.1 in hex form)", () => {
		expect(isPrivateIP("::ffff:0a00:0001")).toBe(true);
	});

	it("blocks ::ffff:c0a8:0101 (192.168.1.1 in hex form)", () => {
		expect(isPrivateIP("::ffff:c0a8:0101")).toBe(true);
	});

	it("blocks ::ffff:a9fe:a9fe (169.254.169.254 metadata in hex form)", () => {
		expect(isPrivateIP("::ffff:a9fe:a9fe")).toBe(true);
	});

	it("blocks ::ffff:ac10:0001 (172.16.0.1 in hex form)", () => {
		expect(isPrivateIP("::ffff:ac10:0001")).toBe(true);
	});

	it("blocks ::ffff:ac1f:ffff (172.31.255.255 upper bound in hex)", () => {
		expect(isPrivateIP("::ffff:ac1f:ffff")).toBe(true);
	});

	it("allows ::ffff:ac20:0001 (172.32.0.1 — just outside RFC 1918 in hex)", () => {
		expect(isPrivateIP("::ffff:ac20:0001")).toBe(false);
	});

	it("allows ::ffff:0101:0101 (1.1.1.1 public DNS in hex form)", () => {
		expect(isPrivateIP("::ffff:0101:0101")).toBe(false);
	});

	it("allows ::ffff:0808:0808 (8.8.8.8 public DNS in hex form)", () => {
		expect(isPrivateIP("::ffff:0808:0808")).toBe(false);
	});

	it("blocks ::FFFF:7F00:1 (mixed case hex form)", () => {
		expect(isPrivateIP("::FFFF:7F00:1")).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// Numeric IPv4 hostnames (decimal and hex integer encodings)
// ---------------------------------------------------------------------------

describe("SSRF regression: numeric IPv4 hostname bypass", () => {
	it("blocks decimal 2130706433 (127.0.0.1)", async () => {
		await expect(resolveHost("2130706433")).rejects.toThrow("SSRF blocked");
	});

	it("blocks hex 0x7f000001 (127.0.0.1)", async () => {
		await expect(resolveHost("0x7f000001")).rejects.toThrow("SSRF blocked");
	});

	it("blocks hex 0x7F000001 (127.0.0.1 uppercase)", async () => {
		await expect(resolveHost("0x7F000001")).rejects.toThrow("SSRF blocked");
	});

	it("blocks decimal 167772161 (10.0.0.1)", async () => {
		await expect(resolveHost("167772161")).rejects.toThrow("SSRF blocked");
	});

	it("blocks hex 0x0a000001 (10.0.0.1)", async () => {
		await expect(resolveHost("0x0a000001")).rejects.toThrow("SSRF blocked");
	});

	it("blocks decimal 3232235777 (192.168.1.1)", async () => {
		await expect(resolveHost("3232235777")).rejects.toThrow("SSRF blocked");
	});

	it("blocks decimal 2852039166 (169.254.169.254 metadata)", async () => {
		await expect(resolveHost("2852039166")).rejects.toThrow("SSRF blocked");
	});

	it("allows decimal 16843009 (1.1.1.1 public DNS)", async () => {
		const ip = await resolveHost("16843009");
		expect(ip).toBe("1.1.1.1");
	});

	it("allows hex 0x01010101 (1.1.1.1 public DNS)", async () => {
		const ip = await resolveHost("0x01010101");
		expect(ip).toBe("1.1.1.1");
	});

	it("allows hex 0x08080808 (8.8.8.8 public DNS)", async () => {
		const ip = await resolveHost("0x08080808");
		expect(ip).toBe("8.8.8.8");
	});

	it("does not treat normal hostnames as numeric", async () => {
		// "example.com" should go through DNS, not numeric parsing
		// We can't easily test DNS here, but verify it doesn't throw "numeric hostname"
		await expect(resolveHost("example.com")).resolves.toBeDefined();
	});

	it("does not treat values above 32-bit range as numeric IPv4", async () => {
		// 4294967296 = 0x100000000, exceeds 32-bit range
		// Should fall through to DNS resolution (which will likely fail)
		await expect(resolveHost("4294967296")).rejects.not.toThrow("numeric hostname");
	});
});
