/**
 * Tests for receipt-request binding: verifying that DecisionDelegate
 * rejects responses where requestHash or requestNonce don't match,
 * preventing receipt substitution attacks.
 */

import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { DecisionSigner, generateSigningKey } from "@arikernel/control-plane";
import { describe, expect, it } from "vitest";
import { DecisionDelegate } from "../src/decision-delegate.js";

const signingKey = generateSigningKey();
const signer = new DecisionSigner(signingKey);
const publicKeyHex = signer.publicKeyHex;

function computeRequestHash(fields: {
	principalId: string;
	toolClass: string;
	action: string;
	parameters: Record<string, unknown>;
	runId: string;
	requestNonce: string;
}): string {
	const canonical = JSON.stringify(
		{
			action: fields.action,
			parameters: fields.parameters,
			principalId: fields.principalId,
			requestNonce: fields.requestNonce,
			runId: fields.runId,
			toolClass: fields.toolClass,
		},
		["action", "parameters", "principalId", "requestNonce", "runId", "toolClass"],
	);
	return createHash("sha256").update(canonical).digest("hex");
}

/** Start a server that signs responses with the real signer, optionally mutating fields. */
function startSigningServer(
	port: number,
	mutate?: (
		reqBody: Record<string, unknown>,
		response: Record<string, unknown>,
	) => Record<string, unknown>,
): Promise<{ close: () => Promise<void> }> {
	return new Promise((resolve) => {
		const server = createServer((req, res) => {
			let data = "";
			req.on("data", (chunk: Buffer) => {
				data += chunk.toString();
			});
			req.on("end", () => {
				const body = JSON.parse(data) as Record<string, unknown>;
				const requestNonce = body.requestNonce as string;

				const requestHash = computeRequestHash({
					principalId: body.principalId as string,
					toolClass: body.toolClass as string,
					action: body.action as string,
					parameters: body.parameters as Record<string, unknown>,
					runId: body.runId as string,
					requestNonce,
				});

				let response = signer.sign({
					decision: "allow",
					reason: "test-allow",
					policyVersion: "1.0.0",
					policyHash: "abcd1234",
					kernelBuild: "test",
					timestamp: new Date().toISOString(),
					taintLabels: [],
					requestHash,
					requestNonce,
				}) as unknown as Record<string, unknown>;

				if (mutate) {
					response = mutate(body, response);
				}

				res.writeHead(200, { "Content-Type": "application/json" });
				res.end(JSON.stringify(response));
			});
		});

		server.listen(port, "127.0.0.1", () => {
			resolve({ close: () => new Promise((r) => server.close(() => r())) });
		});
	});
}

const baseParams = {
	principalId: "agent-1",
	toolClass: "http" as const,
	action: "get",
	parameters: { url: "https://example.com" },
	taintLabels: [],
	runId: "run-binding-1",
};

describe("Receipt-request binding", () => {
	it("accepts a correctly bound receipt", async () => {
		const srv = await startSigningServer(19400);
		try {
			const delegate = new DecisionDelegate({
				controlPlaneUrl: "http://127.0.0.1:19400",
				controlPlanePublicKey: publicKeyHex,
			});

			const result = await delegate.requestDecision(baseParams);
			expect(result).not.toBeNull();
			expect(result?.verdict).toBe("allow");
		} finally {
			await srv.close();
		}
	});

	it("rejects receipt with wrong requestNonce (substituted from different request)", async () => {
		const srv = await startSigningServer(19401, (_body, response) => {
			// Attacker swaps the requestNonce to one from a different request
			// but the signature still covers the original nonce, so sig is valid
			// — however the delegate checks nonce match independently
			return { ...response, requestNonce: "deadbeef".repeat(4) };
		});
		try {
			const delegate = new DecisionDelegate({
				controlPlaneUrl: "http://127.0.0.1:19401",
				controlPlanePublicKey: publicKeyHex,
			});

			const result = await delegate.requestDecision(baseParams);
			// Should be null: sig verification fails because requestNonce in
			// canonical payload doesn't match the tampered field
			expect(result).toBeNull();
		} finally {
			await srv.close();
		}
	});

	it("rejects receipt with wrong requestHash (receipt from different request parameters)", async () => {
		const srv = await startSigningServer(19402, (body, _response) => {
			// Attacker re-signs a receipt for different parameters
			const fakeHash = computeRequestHash({
				principalId: body.principalId as string,
				toolClass: body.toolClass as string,
				action: "delete", // different action
				parameters: {},
				runId: body.runId as string,
				requestNonce: body.requestNonce as string,
			});

			// Re-sign with the wrong hash — signature is valid for the wrong hash
			return signer.sign({
				decision: "allow",
				reason: "test-allow",
				policyVersion: "1.0.0",
				policyHash: "abcd1234",
				kernelBuild: "test",
				timestamp: new Date().toISOString(),
				taintLabels: [],
				requestHash: fakeHash,
				requestNonce: body.requestNonce as string,
			}) as unknown as Record<string, unknown>;
		});
		try {
			const delegate = new DecisionDelegate({
				controlPlaneUrl: "http://127.0.0.1:19402",
				controlPlanePublicKey: publicKeyHex,
			});

			const result = await delegate.requestDecision(baseParams);
			// requestHash won't match what the delegate computes locally
			expect(result).toBeNull();
		} finally {
			await srv.close();
		}
	});

	it("rejects receipt with tampered signature", async () => {
		const srv = await startSigningServer(19403, (_body, response) => {
			// Corrupt the signature
			return { ...response, signature: "ff".repeat(64) };
		});
		try {
			const delegate = new DecisionDelegate({
				controlPlaneUrl: "http://127.0.0.1:19403",
				controlPlanePublicKey: publicKeyHex,
			});

			const result = await delegate.requestDecision(baseParams);
			expect(result).toBeNull();
		} finally {
			await srv.close();
		}
	});
});
