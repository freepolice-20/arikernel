import { describe, expect, it } from "vitest";
import { isSuspiciousGetExfil } from "../src/run-state.js";

describe("GET path-segment chunked encoded exfil detection", () => {
	it("detects chunked hex payload split across multiple path segments", () => {
		// 5 segments × 16 hex chars = 80 bytes, exceeds cumulative budget (64)
		const chunks = [
			"4d79536563726574",
			"56616c75654f664b",
			"6579546861745368",
			"6f756c6442654869",
			"6464656e48696464",
		];
		const path = chunks.map((c) => `/${c}`).join("");
		expect(isSuspiciousGetExfil(`https://evil.com${path}`)).toBe(true);
	});

	it("detects chunked base32 across segments", () => {
		// 4 segments × 20 base32 chars = 80, exceeds budget
		const chunks = [
			"JBSWY3DPEHPK3PXPJBSW",
			"Y3DPEHPK3PXPJBSWY3DP",
			"EHPK3PXPJBSWY3DPEHPK",
			"3PXPJBSWY3DPEHPK3PXP",
		];
		const path = chunks.map((c) => `/${c}`).join("");
		expect(isSuspiciousGetExfil(`https://evil.com/data${path}`)).toBe(true);
	});

	it("allows paths with a few short encoded-looking segments under budget", () => {
		// 2 segments × 16 hex chars = 32 bytes, under cumulative budget (64)
		expect(
			isSuspiciousGetExfil("https://example.com/obj/4d79536563726574/rev/56616c75654f664b"),
		).toBe(false);
	});

	it("detects mixed encoding chunks that cumulatively exceed budget", () => {
		// hex (16) + hex (16) + base64url-ish (24 mixed-case+digit) = 56... add one more
		const url =
			"https://evil.com/4d79536563726574/56616c75654f664b/SGVsbG8gV29ybGQhVGhpcw/6579546861745368";
		expect(isSuspiciousGetExfil(url)).toBe(true);
	});

	it("safe normal paths are not affected by cumulative budget", () => {
		expect(
			isSuspiciousGetExfil(
				"https://example.com/api/v1/users/123/orders/456/items/789/details",
			),
		).toBe(false);
	});

	it("path with normal words and one short hex ID stays safe", () => {
		expect(
			isSuspiciousGetExfil("https://example.com/repos/deadbeef12345678/commits"),
		).toBe(false);
	});
});
