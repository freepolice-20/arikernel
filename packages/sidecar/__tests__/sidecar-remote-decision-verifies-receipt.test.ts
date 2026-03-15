/**
 * Verifies that the sidecar's DecisionDelegate checks Ed25519 signatures
 * and nonces on control-plane decision receipts before trusting them.
 */

import { createHash } from "node:crypto";
import { createServer, type Server } from "node:http";
import { describe, expect, it, afterEach } from "vitest";
import { DecisionSigner, generateSigningKey } from "@arikernel/control-plane";
import { DecisionDelegate } from "../src/decision-delegate.js";

const SEED = generateSigningKey();
const SIGNER = new DecisionSigner(SEED);
const PUBLIC_KEY = SIGNER.publicKeyHex;

function computeRequestHash(reqBody: Record<string, unknown>): string {
	const canonical = JSON.stringify(
		{
			action: reqBody.action,
			parameters: reqBody.parameters,
			principalId: reqBody.principalId,
			requestNonce: reqBody.requestNonce,
			runId: reqBody.runId,
			toolClass: reqBody.toolClass,
		},
		["action", "parameters", "principalId", "requestNonce", "runId", "toolClass"],
	);
	return createHash("sha256").update(canonical).digest("hex");
}

/** Build a valid signed receipt using the test signer, bound to the request. */
function signedReceipt(verdict: "allow" | "deny" = "allow", reqBody?: Record<string, unknown>) {
	const requestNonce = reqBody?.requestNonce as string | undefined;
	const requestHash = reqBody ? computeRequestHash(reqBody) : undefined;
	return SIGNER.sign({
		decision: verdict,
		reason: "test-reason",
		policyVersion: "1.0.0",
		policyHash: "abcdef0123456789",
		kernelBuild: "test-build",
		timestamp: new Date().toISOString(),
		taintLabels: [],
		...(requestHash ? { requestHash } : {}),
		...(requestNonce ? { requestNonce } : {}),
	});
}

/** Start a mock CP server that responds with the given body. */
function startMockCP(
	port: number,
	responseBody: (reqBody: Record<string, unknown>) => unknown,
	statusCode = 200,
): Promise<{ server: Server; close: () => Promise<void> }> {
	return new Promise((resolve) => {
		const server = createServer((_req, res) => {
			let body = "";
			_req.on("data", (c: Buffer) => {
				body += c.toString();
			});
			_req.on("end", () => {
				const parsed = JSON.parse(body) as Record<string, unknown>;
				res.writeHead(statusCode, { "Content-Type": "application/json" });
				res.end(JSON.stringify(responseBody(parsed)));
			});
		});
		server.listen(port, "127.0.0.1", () => {
			resolve({
				server,
				close: () => new Promise((r) => server.close(() => r())),
			});
		});
	});
}

const CALL_PARAMS = {
	principalId: "agent-1",
	toolClass: "http" as const,
	action: "GET",
	parameters: {},
	taintLabels: [],
	runId: "run-1",
};

describe("DecisionDelegate — receipt verification", () => {
	const servers: Array<{ close: () => Promise<void> }> = [];
	afterEach(async () => {
		for (const s of servers) await s.close();
		servers.length = 0;
	});

	it("accepts a valid signed receipt", async () => {
		const mock = await startMockCP(19200, (req) => signedReceipt("allow", req));
		servers.push(mock);

		const delegate = new DecisionDelegate({
			controlPlaneUrl: "http://127.0.0.1:19200",
			controlPlanePublicKey: PUBLIC_KEY,
		});

		const result = await delegate.requestDecision(CALL_PARAMS);
		expect(result).not.toBeNull();
		expect(result!.verdict).toBe("allow");
		expect(result!.decisionId).toMatch(/^dec-/);
		expect(result!.policyHash).toBe("abcdef0123456789");
		expect(result!.kernelBuild).toBe("test-build");
	});

	it("rejects a receipt with a tampered signature", async () => {
		const mock = await startMockCP(19201, (req) => {
			const receipt = signedReceipt("allow", req);
			// Tamper: flip the first byte of the signature
			const tampered = "00" + receipt.signature.slice(2);
			return { ...receipt, signature: tampered };
		});
		servers.push(mock);

		const delegate = new DecisionDelegate({
			controlPlaneUrl: "http://127.0.0.1:19201",
			controlPlanePublicKey: PUBLIC_KEY,
		});

		const result = await delegate.requestDecision(CALL_PARAMS);
		expect(result).toBeNull();
	});

	it("rejects a receipt with a tampered reason field", async () => {
		const mock = await startMockCP(19202, (req) => {
			const receipt = signedReceipt("deny", req);
			return { ...receipt, reason: "manipulated-reason" };
		});
		servers.push(mock);

		const delegate = new DecisionDelegate({
			controlPlaneUrl: "http://127.0.0.1:19202",
			controlPlanePublicKey: PUBLIC_KEY,
		});

		const result = await delegate.requestDecision(CALL_PARAMS);
		expect(result).toBeNull();
	});

	it("rejects a replayed nonce (same receipt sent twice)", async () => {
		let cachedReceipt: unknown;
		const mock = await startMockCP(19203, (req) => {
			if (!cachedReceipt) cachedReceipt = signedReceipt("allow", req);
			return cachedReceipt;
		});
		servers.push(mock);

		const delegate = new DecisionDelegate({
			controlPlaneUrl: "http://127.0.0.1:19203",
			controlPlanePublicKey: PUBLIC_KEY,
		});

		const first = await delegate.requestDecision(CALL_PARAMS);
		expect(first).not.toBeNull();

		// Same receipt replayed — nonce already claimed
		const second = await delegate.requestDecision(CALL_PARAMS);
		expect(second).toBeNull();
	});

	it("rejects a receipt signed by a different key", async () => {
		const otherSeed = generateSigningKey();
		const otherSigner = new DecisionSigner(otherSeed);
		const mock = await startMockCP(19204, (req) => {
			const requestNonce = req.requestNonce as string;
			const requestHash = computeRequestHash(req);
			return otherSigner.sign({
				decision: "allow",
				reason: "wrong-key",
				policyVersion: "1.0.0",
				policyHash: "abcdef0123456789",
				kernelBuild: "test-build",
				timestamp: new Date().toISOString(),
				taintLabels: [],
				requestHash,
				requestNonce,
			});
		});
		servers.push(mock);

		const delegate = new DecisionDelegate({
			controlPlaneUrl: "http://127.0.0.1:19204",
			controlPlanePublicKey: PUBLIC_KEY, // expects original key
		});

		const result = await delegate.requestDecision(CALL_PARAMS);
		expect(result).toBeNull();
	});

	it("skips verification when no public key is configured", async () => {
		const mock = await startMockCP(19205, (_req) => ({
			decision: "allow",
			reason: "no-verify",
			signature: "x".repeat(128),
			nonce: "y".repeat(32),
			policyVersion: "1.0.0",
			decisionId: "dec-fake",
			policyHash: "0000000000000000",
			kernelBuild: "none",
			taintLabels: [],
		}));
		servers.push(mock);

		const delegate = new DecisionDelegate({
			controlPlaneUrl: "http://127.0.0.1:19205",
			// no controlPlanePublicKey — verification skipped
		});

		const result = await delegate.requestDecision(CALL_PARAMS);
		expect(result).not.toBeNull();
		expect(result!.verdict).toBe("allow");
	});

	it("returns deny verdicts after successful verification", async () => {
		const mock = await startMockCP(19206, (req) => signedReceipt("deny", req));
		servers.push(mock);

		const delegate = new DecisionDelegate({
			controlPlaneUrl: "http://127.0.0.1:19206",
			controlPlanePublicKey: PUBLIC_KEY,
		});

		const result = await delegate.requestDecision(CALL_PARAMS);
		expect(result).not.toBeNull();
		expect(result!.verdict).toBe("deny");
		expect(result!.reason).toBe("test-reason");
	});
});
