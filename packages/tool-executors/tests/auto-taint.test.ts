import type { ToolCall } from "@arikernel/core";
import { now } from "@arikernel/core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpExecutor } from "../src/http.js";
import { RetrievalExecutor } from "../src/retrieval.js";

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

describe("HttpExecutor auto-taint", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("tags successful responses with web:<hostname>", async () => {
		vi.stubGlobal("fetch", async () => ({
			ok: true,
			status: 200,
			headers: { get: () => "text/plain", entries: () => [] },
			text: async () => "hello",
		}));

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
		vi.stubGlobal("fetch", async () => {
			throw new Error("network error");
		});

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
		vi.stubGlobal("fetch", async () => {
			throw new Error("fail");
		});

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
		vi.stubGlobal("fetch", async () => ({
			ok: true,
			status: 200,
			headers: { get: () => "application/json", entries: () => [] },
			json: async () => ({ data: "test" }),
		}));

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
