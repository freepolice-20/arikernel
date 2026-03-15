/**
 * GET/HEAD must not carry a request body (RFC 9110 §9.3.1, §9.3.2).
 * Bodies on these methods are a semantic violation and exfil vector.
 */

import type { ToolCall } from "@arikernel/core";
import { now } from "@arikernel/core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpExecutor } from "../src/http.js";

// Mock SSRF module to prevent real network requests
vi.mock("../src/ssrf.js", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../src/ssrf.js")>();
	return {
		...actual,
		ssrfSafeRequest: vi.fn(),
	};
});

import { ssrfSafeRequest } from "../src/ssrf.js";
import type { PinnedResponse } from "../src/ssrf.js";

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

describe("HTTP GET/HEAD body rejection", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("rejects GET with a JSON body", async () => {
		const executor = new HttpExecutor();
		const result = await executor.execute(
			makeToolCall({
				action: "get",
				parameters: {
					url: "https://example.com/api",
					body: { secret: "ssh-rsa AAAA..." },
				},
			}),
		);

		expect(result.success).toBe(false);
		expect(result.error).toContain("must not carry a request body");
		expect(result.error).toContain("exfiltration");
		expect(mockSsrfSafeRequest).not.toHaveBeenCalled();
	});

	it("rejects HEAD with a body", async () => {
		const executor = new HttpExecutor();
		const result = await executor.execute(
			makeToolCall({
				action: "head",
				parameters: {
					url: "https://example.com/api",
					body: "leaked data",
				},
			}),
		);

		expect(result.success).toBe(false);
		expect(result.error).toContain("must not carry a request body");
		expect(mockSsrfSafeRequest).not.toHaveBeenCalled();
	});

	it("rejects GET with an empty object body", async () => {
		const executor = new HttpExecutor();
		const result = await executor.execute(
			makeToolCall({
				action: "get",
				parameters: { url: "https://example.com/api", body: {} },
			}),
		);

		expect(result.success).toBe(false);
		expect(result.error).toContain("must not carry a request body");
		expect(mockSsrfSafeRequest).not.toHaveBeenCalled();
	});

	it("allows GET without a body (normal usage)", async () => {
		mockSsrfSafeRequest.mockResolvedValue(mockOkResponse());
		const executor = new HttpExecutor();
		const result = await executor.execute(
			makeToolCall({
				action: "get",
				parameters: { url: "https://example.com/page" },
			}),
		);

		expect(result.success).toBe(true);
		expect(mockSsrfSafeRequest).toHaveBeenCalled();
	});

	it("allows GET with body: undefined", async () => {
		mockSsrfSafeRequest.mockResolvedValue(mockOkResponse());
		const executor = new HttpExecutor();
		const result = await executor.execute(
			makeToolCall({
				action: "get",
				parameters: { url: "https://example.com/page", body: undefined },
			}),
		);

		expect(result.success).toBe(true);
	});

	it("allows GET with body: null", async () => {
		mockSsrfSafeRequest.mockResolvedValue(mockOkResponse());
		const executor = new HttpExecutor();
		const result = await executor.execute(
			makeToolCall({
				action: "get",
				parameters: { url: "https://example.com/page", body: null },
			}),
		);

		expect(result.success).toBe(true);
	});

	it("still allows POST with a body", async () => {
		mockSsrfSafeRequest.mockResolvedValue(mockOkResponse());
		const executor = new HttpExecutor();
		const result = await executor.execute(
			makeToolCall({
				action: "post",
				parameters: {
					url: "https://example.com/api",
					body: { data: "payload" },
				},
			}),
		);

		expect(result.success).toBe(true);
		expect(mockSsrfSafeRequest).toHaveBeenCalled();
	});

	it("still allows PUT with a body", async () => {
		mockSsrfSafeRequest.mockResolvedValue(mockOkResponse());
		const executor = new HttpExecutor();
		const result = await executor.execute(
			makeToolCall({
				action: "put",
				parameters: {
					url: "https://example.com/api",
					body: { data: "update" },
				},
			}),
		);

		expect(result.success).toBe(true);
	});
});
