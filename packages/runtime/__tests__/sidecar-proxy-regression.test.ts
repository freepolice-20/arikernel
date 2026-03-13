/**
 * Regression test: SidecarProxyExecutor must distinguish security denials
 * from tool execution failures.
 *
 * - Security denial (HTTP 403 / allowed=false) → throws ToolCallDeniedError
 * - Tool failure (HTTP 200, allowed=true, success=false) → returns ToolResult{success:false}
 *
 * A missing file (ENOENT) should NOT increment denied-action counters or
 * trigger quarantine.
 */
import http from "node:http";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { ToolCallDeniedError, now } from "@arikernel/core";
import { SidecarProxyExecutor } from "../src/sidecar-proxy.js";
import type { ToolCall } from "@arikernel/core";

function makeToolCall(overrides?: Partial<ToolCall>): ToolCall {
	return {
		id: "call-001",
		runId: "run-001",
		sequence: 1,
		timestamp: now(),
		principalId: "test-agent",
		toolClass: "file",
		action: "read",
		parameters: { path: "/nonexistent/file.txt" },
		taintLabels: [],
		...overrides,
	};
}

/** Minimal HTTP server that returns canned responses based on the request. */
function createFakeSidecar(
	handler: (body: Record<string, unknown>) => { status: number; json: Record<string, unknown> },
): http.Server {
	return http.createServer((req, res) => {
		let data = "";
		req.on("data", (chunk: string) => {
			data += chunk;
		});
		req.on("end", () => {
			const body = JSON.parse(data) as Record<string, unknown>;
			const response = handler(body);
			res.writeHead(response.status, { "Content-Type": "application/json" });
			res.end(JSON.stringify(response.json));
		});
	});
}

describe("SidecarProxyExecutor: denial vs tool failure", () => {
	let server: http.Server;
	let port: number;

	// Holds the response to return for the next request
	let nextResponse: { status: number; json: Record<string, unknown> };

	beforeAll(async () => {
		server = createFakeSidecar((_body) => nextResponse);
		await new Promise<void>((resolve) => {
			server.listen(0, "127.0.0.1", () => resolve());
		});
		const addr = server.address() as { port: number };
		port = addr.port;
	});

	afterAll(async () => {
		await new Promise<void>((resolve) => {
			server.close(() => resolve());
		});
	});

	it("returns ToolResult{success:false} for tool failure (allowed=true, success=false)", async () => {
		nextResponse = {
			status: 200,
			json: {
				allowed: true,
				success: false,
				error: "ENOENT: no such file or directory",
				callId: "call-001",
			},
		};

		const executor = new SidecarProxyExecutor("file", {
			baseUrl: `http://127.0.0.1:${port}`,
			principalId: "test-agent",
		});

		const result = await executor.execute(makeToolCall());

		// Should NOT throw — this is a tool failure, not a security denial
		expect(result.success).toBe(false);
		expect(result.error).toBe("ENOENT: no such file or directory");
		expect(result.data).toBeUndefined();
		expect(result.callId).toBe("call-001");
	});

	it("throws ToolCallDeniedError for security denial (HTTP 403, allowed=false)", async () => {
		nextResponse = {
			status: 403,
			json: {
				allowed: false,
				error: "Policy denied: path outside allowed jail",
				callId: "call-002",
			},
		};

		const executor = new SidecarProxyExecutor("file", {
			baseUrl: `http://127.0.0.1:${port}`,
			principalId: "test-agent",
		});

		await expect(executor.execute(makeToolCall({ id: "call-002" }))).rejects.toThrow(
			ToolCallDeniedError,
		);
	});

	it("throws ToolCallDeniedError for allowed=false with HTTP 200", async () => {
		// Edge case: some older sidecar versions might return 200 with allowed=false
		nextResponse = {
			status: 200,
			json: {
				allowed: false,
				error: "Denied by quarantine",
				callId: "call-003",
			},
		};

		const executor = new SidecarProxyExecutor("file", {
			baseUrl: `http://127.0.0.1:${port}`,
			principalId: "test-agent",
		});

		await expect(executor.execute(makeToolCall({ id: "call-003" }))).rejects.toThrow(
			ToolCallDeniedError,
		);
	});

	it("returns ToolResult{success:true} for successful execution", async () => {
		nextResponse = {
			status: 200,
			json: {
				allowed: true,
				success: true,
				result: "file contents here",
				callId: "call-004",
			},
		};

		const executor = new SidecarProxyExecutor("file", {
			baseUrl: `http://127.0.0.1:${port}`,
			principalId: "test-agent",
		});

		const result = await executor.execute(makeToolCall({ id: "call-004" }));

		expect(result.success).toBe(true);
		expect(result.data).toBe("file contents here");
		expect(result.error).toBeUndefined();
	});

	it("defaults success=true when success field is omitted (backward compat)", async () => {
		// Older sidecars may not include the success field
		nextResponse = {
			status: 200,
			json: {
				allowed: true,
				result: "data",
				callId: "call-005",
			},
		};

		const executor = new SidecarProxyExecutor("file", {
			baseUrl: `http://127.0.0.1:${port}`,
			principalId: "test-agent",
		});

		const result = await executor.execute(makeToolCall({ id: "call-005" }));

		expect(result.success).toBe(true);
		expect(result.data).toBe("data");
	});
});
