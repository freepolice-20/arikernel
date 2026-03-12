/**
 * NF-07: DecisionDelegate must include a per-request nonce in every
 * outbound decision request to prevent replay attacks against the
 * control plane.
 */

import { createServer } from "node:http";
import { describe, expect, it } from "vitest";
import { DecisionDelegate } from "../src/decision-delegate.js";

/** Start a minimal HTTP server that records the last request body and always returns 200. */
function startCaptureServer(port: number): Promise<{
	lastBody: () => Record<string, unknown> | null;
	close: () => Promise<void>;
}> {
	return new Promise((resolve) => {
		let lastBody: Record<string, unknown> | null = null;

		const server = createServer((req, res) => {
			let data = "";
			req.on("data", (chunk: Buffer) => {
				data += chunk.toString();
			});
			req.on("end", () => {
				try {
					lastBody = JSON.parse(data) as Record<string, unknown>;
				} catch {
					lastBody = null;
				}
				res.writeHead(200, { "Content-Type": "application/json" });
				res.end(
					JSON.stringify({
						verdict: "allow",
						reason: "test",
						signature: "a".repeat(128),
						nonce: "b".repeat(32),
						policyVersion: "1.0.0",
						taintLabels: [],
					}),
				);
			});
		});

		server.listen(port, "127.0.0.1", () => {
			resolve({
				lastBody: () => lastBody,
				close: () => new Promise((res) => server.close(() => res())),
			});
		});
	});
}

describe("DecisionDelegate — requestNonce (NF-07)", () => {
	it("includes requestNonce in every outbound decision request", async () => {
		const capture = await startCaptureServer(19100);
		try {
			const delegate = new DecisionDelegate({
				controlPlaneUrl: "http://127.0.0.1:19100",
			});

			await delegate.requestDecision({
				principalId: "agent-1",
				toolClass: "http",
				action: "get",
				parameters: {},
				taintLabels: [],
				runId: "run-1",
			});

			const body = capture.lastBody();
			expect(body).not.toBeNull();
			expect(body?.requestNonce).toBeDefined();
			expect(typeof body?.requestNonce).toBe("string");
			// 16 bytes = 32 hex chars
			expect((body?.requestNonce as string).length).toBe(32);
			expect(body?.requestNonce as string).toMatch(/^[0-9a-f]{32}$/);
		} finally {
			await capture.close();
		}
	});

	it("generates a unique nonce per request", async () => {
		const capture = await startCaptureServer(19101);
		const nonces: string[] = [];

		try {
			const delegate = new DecisionDelegate({
				controlPlaneUrl: "http://127.0.0.1:19101",
			});

			for (let i = 0; i < 5; i++) {
				await delegate.requestDecision({
					principalId: "agent-1",
					toolClass: "http",
					action: "get",
					parameters: {},
					taintLabels: [],
					runId: `run-${i}`,
				});
				const body = capture.lastBody();
				if (body?.requestNonce) {
					nonces.push(body.requestNonce as string);
				}
			}

			// All nonces should be unique
			const unique = new Set(nonces);
			expect(unique.size).toBe(nonces.length);
		} finally {
			await capture.close();
		}
	});
});
