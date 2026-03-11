import { readFileSync } from "node:fs";
import { DecisionVerifier, NonceStore } from "@arikernel/control-plane";
import type { DecisionResponse } from "@arikernel/control-plane";

const REQUIRED_FIELDS: (keyof DecisionResponse)[] = [
	"decision",
	"decisionId",
	"reason",
	"policyVersion",
	"policyHash",
	"kernelBuild",
	"timestamp",
	"nonce",
	"signature",
];

export function runVerifyReceipt(receiptPath: string, publicKey?: string): void {
	let raw: string;
	try {
		raw = readFileSync(receiptPath, "utf-8");
	} catch {
		console.error(`Error: Cannot read file '${receiptPath}'`);
		process.exitCode = 1;
		return;
	}

	let receipt: Record<string, unknown>;
	try {
		receipt = JSON.parse(raw) as Record<string, unknown>;
	} catch {
		console.error("Error: File is not valid JSON");
		process.exitCode = 1;
		return;
	}

	console.log("=== AriKernel Receipt Verification ===\n");

	// Check required fields
	const missingFields: string[] = [];
	for (const field of REQUIRED_FIELDS) {
		if (receipt[field] == null || receipt[field] === "") {
			missingFields.push(field);
		}
	}

	if (missingFields.length > 0) {
		console.log(`Required fields: FAIL — missing: ${missingFields.join(", ")}`);
		process.exitCode = 1;
	} else {
		console.log("Required fields: PASS");
	}

	// Display receipt metadata
	console.log(`\nDecision:       ${receipt.decision ?? "—"}`);
	console.log(`Decision ID:    ${receipt.decisionId ?? "—"}`);
	console.log(`Policy version: ${receipt.policyVersion ?? "—"}`);
	console.log(`Policy hash:    ${receipt.policyHash ?? "—"}`);
	console.log(`Kernel build:   ${receipt.kernelBuild ?? "—"}`);
	console.log(`Timestamp:      ${receipt.timestamp ?? "—"}`);
	console.log(`Nonce:          ${receipt.nonce ?? "—"}`);

	// Verify signature if public key is provided
	if (publicKey) {
		try {
			const verifier = new DecisionVerifier(publicKey);
			const valid = verifier.verify(receipt as unknown as DecisionResponse);
			console.log(`\nSignature:      ${valid ? "VALID" : "INVALID"}`);
			if (!valid) process.exitCode = 1;
		} catch (e) {
			console.log(`\nSignature:      ERROR — ${(e as Error).message}`);
			process.exitCode = 1;
		}
	} else {
		console.log("\nSignature:      SKIPPED (no --public-key provided)");
	}

	// Payload integrity — verify nonce format (32 hex chars)
	const nonce = String(receipt.nonce ?? "");
	const nonceValid = /^[0-9a-f]{32}$/.test(nonce);
	console.log(`Nonce format:   ${nonceValid ? "PASS" : "FAIL"}`);

	// Signature format (128 hex chars = 64 bytes Ed25519)
	const sig = String(receipt.signature ?? "");
	const sigFormat = /^[0-9a-f]{128}$/.test(sig);
	console.log(`Sig format:     ${sigFormat ? "PASS" : "FAIL"}`);

	if (!nonceValid || !sigFormat) process.exitCode = 1;

	console.log("\n=== Verification complete ===");
}
