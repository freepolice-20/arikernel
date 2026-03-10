import { describe, expect, it } from "vitest";
import { isPrivateIP } from "../src/http.js";

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
});
