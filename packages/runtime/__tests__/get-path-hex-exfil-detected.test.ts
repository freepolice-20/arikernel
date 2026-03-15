import { describe, expect, it } from "vitest";
import { isSuspiciousGetExfil } from "../src/run-state.js";

describe("GET path-segment hex exfil detection", () => {
	it("detects long hex payload in path segment", () => {
		// 64 hex chars — a 32-byte secret encoded as hex
		const hexPayload = "4d7953656372657456616c75654f664b65795468617453686f756c64426548696464656e";
		expect(isSuspiciousGetExfil(`https://evil.com/leak/${hexPayload}`)).toBe(true);
	});

	it("detects 16-char hex segment as suspicious", () => {
		const hex16 = "4d79536563726574"; // 16 hex chars
		// Single 16-char segment doesn't exceed cumulative budget alone,
		// but is recognized as encoded. Two such segments exceed budget.
		expect(
			isSuspiciousGetExfil(`https://evil.com/a/${hex16}/b/${hex16}/c/${hex16}/d/${hex16}/e/${hex16}`),
		).toBe(true);
	});

	it("allows normal short hex-like path segments (UUIDs, short IDs)", () => {
		// A UUID is 32 hex chars + 4 hyphens — the hyphens break hex detection
		expect(
			isSuspiciousGetExfil("https://example.com/users/550e8400-e29b-41d4-a716-446655440000/profile"),
		).toBe(false);
	});

	it("allows normal REST paths", () => {
		expect(isSuspiciousGetExfil("https://example.com/users/123/profile")).toBe(false);
		expect(isSuspiciousGetExfil("https://example.com/api/v1/orders/abc123")).toBe(false);
		expect(isSuspiciousGetExfil("https://example.com/api/v2/items")).toBe(false);
	});

	it("allows short hex IDs under threshold", () => {
		// 8 hex chars — too short to flag
		expect(isSuspiciousGetExfil("https://example.com/commits/a1b2c3d4")).toBe(false);
	});

	it("detects base32-like payload in path segment", () => {
		// 32-char base32 payload
		const base32 = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
		expect(isSuspiciousGetExfil(`https://evil.com/exfil/${base32}`)).toBe(true);
	});

	it("detects base64url payload in path segment", () => {
		// 28-char base64url payload (mixed case + digits)
		const b64url = "SGVsbG8tV29ybGRfVGhpc0lzMQ";
		expect(isSuspiciousGetExfil(`https://evil.com/data/${b64url}`)).toBe(true);
	});

	it("does not flag normal lowercase-only path words", () => {
		expect(
			isSuspiciousGetExfil("https://example.com/notifications/authentication/authorization"),
		).toBe(false);
	});
});
