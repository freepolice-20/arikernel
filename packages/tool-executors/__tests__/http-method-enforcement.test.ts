import type { ToolCall } from "@arikernel/core";
import { now } from "@arikernel/core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpExecutor } from "../src/http.js";
import type { PinnedResponse } from "../src/ssrf.js";

// Mock the ssrf module so we don't make real network requests
vi.mock("../src/ssrf.js", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../src/ssrf.js")>();
	return {
		...actual,
		ssrfSafeRequest: vi.fn(),
	};
});

import { ssrfSafeRequest } from "../src/ssrf.js";

const mockSsrfSafeRequest = vi.mocked(ssrfSafeRequest);

function makeToolCall(overrides: Partial<ToolCall> = {}): ToolCall {
	return {
		id: "test-id",
		runId: "run-1",
		sequence: 0,
		timestamp: now(),
		principalId: "agent",
		toolClass: "http",
		action: "get",
		parameters: { url: "https://example.com/page" },
		taintLabels: [],
		...overrides,
	};
}

function mockOkResponse(): PinnedResponse {
	return {
		status: 200,
		headers: { "content-type": "text/plain" },
		body: "ok",
		redirectChain: [],
	};
}

describe("HTTP method enforcement", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("rejects action=get with params.method=POST (policy bypass attempt)", async () => {
		const executor = new HttpExecutor();
		const result = await executor.execute(
			makeToolCall({
				action: "get",
				parameters: { url: "https://example.com/api", method: "POST" },
			}),
		);

		expect(result.success).toBe(false);
		expect(result.error).toContain("method mismatch");
		expect(result.error).toContain("policy bypass");
		// ssrfSafeRequest should never be called for a mismatch
		expect(mockSsrfSafeRequest).not.toHaveBeenCalled();
	});

	it("rejects action=get with params.method=DELETE", async () => {
		const executor = new HttpExecutor();
		const result = await executor.execute(
			makeToolCall({
				action: "get",
				parameters: { url: "https://example.com/api", method: "DELETE" },
			}),
		);

		expect(result.success).toBe(false);
		expect(result.error).toContain("method mismatch");
		expect(mockSsrfSafeRequest).not.toHaveBeenCalled();
	});

	it("rejects action=post with params.method=GET", async () => {
		const executor = new HttpExecutor();
		const result = await executor.execute(
			makeToolCall({
				action: "post",
				parameters: { url: "https://example.com/api", method: "GET", body: "{}" },
			}),
		);

		expect(result.success).toBe(false);
		expect(result.error).toContain("method mismatch");
		expect(mockSsrfSafeRequest).not.toHaveBeenCalled();
	});

	it("rejects case-insensitive mismatch (action=get, method=post)", async () => {
		const executor = new HttpExecutor();
		const result = await executor.execute(
			makeToolCall({
				action: "get",
				parameters: { url: "https://example.com/api", method: "post" },
			}),
		);

		expect(result.success).toBe(false);
		expect(result.error).toContain("method mismatch");
	});

	it("allows matching action and params.method (action=get, method=GET)", async () => {
		mockSsrfSafeRequest.mockResolvedValue(mockOkResponse());
		const executor = new HttpExecutor();
		const result = await executor.execute(
			makeToolCall({
				action: "get",
				parameters: { url: "https://example.com/page", method: "GET" },
			}),
		);

		expect(result.success).toBe(true);
	});

	it("allows matching with different case (action=post, method=post)", async () => {
		mockSsrfSafeRequest.mockResolvedValue(mockOkResponse());
		const executor = new HttpExecutor();
		const result = await executor.execute(
			makeToolCall({
				action: "post",
				parameters: { url: "https://example.com/api", method: "post", body: "{}" },
			}),
		);

		expect(result.success).toBe(true);
	});

	it("works without params.method (derives from action)", async () => {
		mockSsrfSafeRequest.mockResolvedValue(mockOkResponse());
		const executor = new HttpExecutor();
		const result = await executor.execute(
			makeToolCall({
				action: "get",
				parameters: { url: "https://example.com/page" },
			}),
		);

		expect(result.success).toBe(true);
	});

	it("rejects unknown action", async () => {
		const executor = new HttpExecutor();
		const result = await executor.execute(
			makeToolCall({
				action: "EXECUTE",
				parameters: { url: "https://example.com/page" },
			}),
		);

		expect(result.success).toBe(false);
		expect(result.error).toContain("Unknown HTTP action");
		expect(mockSsrfSafeRequest).not.toHaveBeenCalled();
	});

	it("canonicalizes all standard HTTP methods", async () => {
		mockSsrfSafeRequest.mockResolvedValue(mockOkResponse());
		const executor = new HttpExecutor();

		for (const action of ["get", "post", "put", "patch", "delete", "head", "options"]) {
			const result = await executor.execute(
				makeToolCall({
					action,
					parameters: { url: "https://example.com/page" },
				}),
			);
			if (result.error) {
				expect(result.error).not.toContain("Unknown HTTP action");
			}
		}
	});

	it("prevents write via read action (the core exploit)", async () => {
		const executor = new HttpExecutor();

		// Attempt the exploit: action=get but method=POST
		const result = await executor.execute(
			makeToolCall({
				action: "get",
				parameters: { url: "https://example.com/api", method: "POST" },
			}),
		);

		// The exploit must be blocked — no network request should be made
		expect(result.success).toBe(false);
		expect(mockSsrfSafeRequest).not.toHaveBeenCalled();
	});

	it("uses action-derived method for actual request", async () => {
		mockSsrfSafeRequest.mockResolvedValue(mockOkResponse());
		const executor = new HttpExecutor();
		await executor.execute(
			makeToolCall({
				action: "post",
				parameters: { url: "https://example.com/api", body: "{}" },
			}),
		);

		expect(mockSsrfSafeRequest).toHaveBeenCalledWith(
			"https://example.com/api",
			"POST",
			expect.any(Object),
			expect.any(String),
			expect.any(Number),
			expect.any(Number),
		);
	});

	it("action=put sends PUT, not overridable", async () => {
		mockSsrfSafeRequest.mockResolvedValue(mockOkResponse());
		const executor = new HttpExecutor();

		// Try to downgrade PUT to GET
		const result = await executor.execute(
			makeToolCall({
				action: "put",
				parameters: { url: "https://example.com/api", method: "GET" },
			}),
		);

		expect(result.success).toBe(false);
		expect(result.error).toContain("method mismatch");
		expect(mockSsrfSafeRequest).not.toHaveBeenCalled();
	});
});
