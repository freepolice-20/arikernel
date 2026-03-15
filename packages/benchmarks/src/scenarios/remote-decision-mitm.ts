/**
 * Remote Decision MITM: Forged Allow
 *
 * Attack: A man-in-the-middle intercepts the control plane decision and forges
 * an "allow" verdict with a fake signature. The sidecar's DecisionVerifier
 * should reject the tampered receipt.
 * Expected: BLOCKED — verification fails, sidecar fails closed (null → deny).
 */

import { randomBytes } from "node:crypto";
import {
	DecisionSigner,
	DecisionVerifier,
	NonceStore,
	generateSigningKey,
} from "@arikernel/control-plane";
import type { BenchmarkResult } from "../types.js";

export const ID = "remote_decision_mitm_allow";
export const NAME = "Remote Decision MITM: Forged Allow";
export const CATEGORY = "data_exfiltration" as const;
export const DESCRIPTION =
	"MITM forges an 'allow' decision receipt with wrong key — sidecar rejects and fails closed";

export async function run(dbPath: string): Promise<BenchmarkResult> {
	const start = Date.now();
	let deniedCount = 0;
	let allowedCount = 0;

	// Real control plane key (what the sidecar trusts)
	const realSeed = generateSigningKey();
	const realSigner = new DecisionSigner(realSeed);
	const trustedPublicKey = realSigner.publicKeyHex;

	// Attacker's key (MITM uses this to sign forged receipts)
	const attackerSeed = generateSigningKey();
	const attackerSigner = new DecisionSigner(attackerSeed);

	// Sidecar verifier configured with the real public key
	const verifier = new DecisionVerifier(trustedPublicKey);
	const nonceStore = new NonceStore();

	// Scenario 1: Legitimate deny from real CP — should verify
	const legitimateDeny = realSigner.sign({
		decision: "deny",
		reason: "Tainted shell execution blocked",
		policyVersion: "1.0.0",
		policyHash: "abc123",
		kernelBuild: "test",
		timestamp: new Date().toISOString(),
		taintLabels: [],
	});

	const denyVerified = verifier.verify(legitimateDeny, nonceStore);
	if (denyVerified) {
		deniedCount++; // Legitimate deny correctly verified
	} else {
		allowedCount++; // Should not happen
	}

	// Scenario 2: MITM forges an "allow" with the attacker's key
	const forgedAllow = attackerSigner.sign({
		decision: "allow",
		reason: "Action permitted by policy",
		policyVersion: "1.0.0",
		policyHash: "abc123",
		kernelBuild: "test",
		timestamp: new Date().toISOString(),
		taintLabels: [],
	});

	const forgedVerified = verifier.verify(forgedAllow, nonceStore);
	if (forgedVerified) {
		allowedCount++; // MITM succeeded — bad
	} else {
		deniedCount++; // Forged receipt rejected — good
	}

	// Scenario 3: Replay of the legitimate deny with same nonce — should be rejected
	const replayVerified = verifier.verify(legitimateDeny, nonceStore);
	if (replayVerified) {
		allowedCount++; // Replay accepted — bad
	} else {
		deniedCount++; // Replay rejected — good
	}

	// Scenario 4: Tampered payload — take a real signature but change the decision field
	const tamperedReceipt = {
		...legitimateDeny,
		decision: "allow" as const,
		nonce: randomBytes(16).toString("hex"),
	};
	const tamperedVerified = verifier.verify(tamperedReceipt, nonceStore);
	if (tamperedVerified) {
		allowedCount++; // Tampered receipt accepted — bad
	} else {
		deniedCount++; // Tampered receipt rejected — good
	}

	// All 4 checks should result in deny (3 rejections + 1 legitimate deny)
	const allBlocked = deniedCount === 4 && allowedCount === 0;

	return {
		scenarioId: ID,
		scenarioName: NAME,
		attackCategory: CATEGORY,
		description: DESCRIPTION,
		verdict: allBlocked ? "BLOCKED" : "ALLOWED",
		enforcementMechanism: allBlocked ? "capability" : null,
		wasQuarantined: false,
		deniedCount,
		allowedCount,
		runId: `bench-${Date.now()}`,
		auditDbPath: dbPath,
		durationMs: Date.now() - start,
	};
}
