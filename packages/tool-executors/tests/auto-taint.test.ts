import type { ToolCall } from "@arikernel/core";
import { now } from "@arikernel/core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpExecutor } from "../src/http.js";
import { RetrievalExecutor } from "../src/retrieval.js";
import type { PinnedResponse } from "../src/ssrf.js";

// Mock the ssrf module so HttpExecutor tests don't make real network requests
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

function mockOkResponse(contentType = "text/plain", body = "hello"): PinnedResponse {
	return {
		status: 200,
		headers: { "content-type": contentType },
		body,
		redirectChain: [],
	};
}

describe("HttpExecutor auto-taint", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("tags successful responses with web:<hostname>", async () => {
		mockSsrfSafeRequest.mockResolvedValue(mockOkResponse());

		const executor = new HttpExecutor();
		const result = await executor.execute(
			makeToolCall({
				parameters: { url: "https://example.com/page" },
			}),
		);

		expect(result.taintLabels).toHaveLength(1);
		expect(result.taintLabels[0].source).toBe("web");
		expect(result.taintLabels[0].origin).toBe("example.com");
		expect(result.taintLabels[0].confidence).toBe(1.0);
	});

	it("tags failed/error responses with web:<hostname>", async () => {
		mockSsrfSafeRequest.mockRejectedValue(new Error("network error"));

		const executor = new HttpExecutor();
		const result = await executor.execute(
			makeToolCall({
				parameters: { url: "https://evil.com/payload" },
			}),
		);

		expect(result.success).toBe(false);
		expect(result.taintLabels).toHaveLength(1);
		expect(result.taintLabels[0].source).toBe("web");
		expect(result.taintLabels[0].origin).toBe("evil.com");
	});

	it("uses full url as origin when url is not parseable", async () => {
		// With an unparseable URL, the executor will fail before calling ssrfSafeRequest
		// because new URL() in ssrfSafeRequest will throw
		mockSsrfSafeRequest.mockRejectedValue(new Error("Invalid URL"));

		const executor = new HttpExecutor();
		const result = await executor.execute(
			makeToolCall({
				parameters: { url: "not-a-valid-url" },
			}),
		);

		expect(result.taintLabels[0].source).toBe("web");
		expect(result.taintLabels[0].origin).toBe("not-a-valid-url");
	});

	it("uses hostname from subdomain URLs", async () => {
		mockSsrfSafeRequest.mockResolvedValue(mockOkResponse("application/json", '{"data":"test"}'));

		const executor = new HttpExecutor();
		const result = await executor.execute(
			makeToolCall({
				parameters: { url: "https://api.github.com/repos/example" },
			}),
		);

		expect(result.taintLabels[0].source).toBe("web");
		expect(result.taintLabels[0].origin).toBe("api.github.com");
	});
});

describe("RetrievalExecutor auto-taint", () => {
	it("tags output with rag:<source>", async () => {
		const executor = new RetrievalExecutor();
		const result = await executor.execute(
			makeToolCall({
				toolClass: "retrieval",
				action: "search",
				parameters: { source: "customer_docs", query: "refund policy" },
			}),
		);

		expect(result.success).toBe(true);
		expect(result.taintLabels).toHaveLength(1);
		expect(result.taintLabels[0].source).toBe("rag");
		expect(result.taintLabels[0].origin).toBe("customer_docs");
		expect(result.taintLabels[0].confidence).toBe(1.0);
	});

	it("uses the source parameter as the taint origin", async () => {
		const executor = new RetrievalExecutor();
		const result = await executor.execute(
			makeToolCall({
				toolClass: "retrieval",
				action: "search",
				parameters: { source: "internal_wiki" },
			}),
		);

		expect(result.taintLabels[0].origin).toBe("internal_wiki");
	});
});
