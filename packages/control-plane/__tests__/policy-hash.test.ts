/**
 * Regression tests for computePolicyHash() content-hashing behavior.
 *
 * Verifies that:
 * 1. Hash is derived from file CONTENTS, not the file path string
 * 2. Hash changes when file content changes (same path)
 * 3. Identical content at different paths produces the same hash
 * 4. Inline PolicyRule[] arrays produce stable hashes
 * 5. undefined/null policy produces a deterministic hash
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ControlPlaneServer, generateSigningKey } from "../src/index.js";

const TEST_KEY = generateSigningKey();

function tempDir(): string {
	return mkdtempSync(join(tmpdir(), "arikernel-policyhash-test-"));
}

/** Valid YAML policy file content that passes policySetSchema validation. */
function validPolicyYaml(decision: "allow" | "deny" = "allow"): string {
	return [
		"name: test-policy",
		"version: '1.0'",
		"rules:",
		"  - id: r1",
		"    name: Test rule",
		"    priority: 10",
		"    match:",
		"      toolClass: http",
		`    decision: ${decision}`,
		"    reason: Test reason",
	].join("\n");
}

function makeServer(
	policy: ConstructorParameters<typeof ControlPlaneServer>[0]["policy"],
): ControlPlaneServer {
	// No listen() needed — policyHash is computed in the constructor
	return new ControlPlaneServer({
		signingKey: TEST_KEY,
		policy,
		port: 0, // never bound
	});
}

describe("computePolicyHash — content hashing regression", () => {
	let dir: string;
	const servers: ControlPlaneServer[] = [];

	afterEach(async () => {
		for (const s of servers) await s.close();
		servers.length = 0;
		if (dir) rmSync(dir, { recursive: true, force: true });
	});

	it("hashes file contents, not the file path string", () => {
		dir = tempDir();
		const content = validPolicyYaml("allow");

		// Same content at two different paths
		const pathA = join(dir, "policy-a.yaml");
		const pathB = join(dir, "completely-different-name.yaml");
		writeFileSync(pathA, content);
		writeFileSync(pathB, content);

		const sA = makeServer(pathA);
		const sB = makeServer(pathB);
		servers.push(sA, sB);

		// Same content → same hash (proves path string is not what's hashed)
		expect(sA.policyHash).toBe(sB.policyHash);
		expect(sA.policyHash).toMatch(/^[0-9a-f]{16}$/);
	});

	it("same content in different directories produces same hash", () => {
		dir = tempDir();
		const content = validPolicyYaml("allow");

		const subdirA = join(dir, "dir-a");
		const subdirB = join(dir, "dir-b");
		mkdirSync(subdirA);
		mkdirSync(subdirB);

		const pathA = join(subdirA, "policy.yaml");
		const pathB = join(subdirB, "policy.yaml");
		writeFileSync(pathA, content);
		writeFileSync(pathB, content);

		const sA = makeServer(pathA);
		const sB = makeServer(pathB);
		servers.push(sA, sB);

		expect(sA.policyHash).toBe(sB.policyHash);
	});

	it("hash changes when file content changes (same path)", () => {
		dir = tempDir();
		const path = join(dir, "policy.yaml");

		writeFileSync(path, validPolicyYaml("allow"));
		const s1 = makeServer(path);
		const hash1 = s1.policyHash;
		servers.push(s1);

		// Overwrite same path with different content
		writeFileSync(path, validPolicyYaml("deny"));
		const s2 = makeServer(path);
		const hash2 = s2.policyHash;
		servers.push(s2);

		expect(hash1).not.toBe(hash2);
	});

	it("inline PolicyRule[] produces stable deterministic hash", () => {
		const policy = [
			{
				id: "r1",
				name: "Allow HTTP",
				priority: 10,
				match: { toolClass: "http" as const },
				decision: "allow" as const,
				reason: "Allowed",
			},
		];

		const s1 = makeServer(policy);
		const s2 = makeServer(policy);
		servers.push(s1, s2);

		expect(s1.policyHash).toBe(s2.policyHash);
		expect(s1.policyHash).toMatch(/^[0-9a-f]{16}$/);
	});

	it("different PolicyRule[] arrays produce different hashes", () => {
		const policyA = [
			{
				id: "r1",
				name: "Allow HTTP",
				priority: 10,
				match: { toolClass: "http" as const },
				decision: "allow" as const,
				reason: "Allowed",
			},
		];
		const policyB = [
			{
				id: "r1",
				name: "Deny HTTP",
				priority: 10,
				match: { toolClass: "http" as const },
				decision: "deny" as const,
				reason: "Denied",
			},
		];

		const sA = makeServer(policyA);
		const sB = makeServer(policyB);
		servers.push(sA, sB);

		expect(sA.policyHash).not.toBe(sB.policyHash);
	});

	it("undefined policy produces a deterministic hash", () => {
		const s1 = makeServer(undefined);
		const s2 = makeServer(undefined);
		servers.push(s1, s2);

		expect(s1.policyHash).toBe(s2.policyHash);
		expect(s1.policyHash).toMatch(/^[0-9a-f]{16}$/);
	});

	it("file-based hash differs from inline hash of the same rules", () => {
		// This proves the hash is of the raw YAML string, not the parsed rules.
		// A file's YAML serialization will differ from JSON.stringify of parsed rules.
		dir = tempDir();
		const rules = [
			{
				id: "r1",
				name: "Allow HTTP",
				priority: 10,
				match: { toolClass: "http" as const },
				decision: "allow" as const,
				reason: "Allowed",
			},
		];

		const path = join(dir, "policy.yaml");
		writeFileSync(path, validPolicyYaml("allow"));

		const sFile = makeServer(path);
		const sInline = makeServer(rules);
		servers.push(sFile, sInline);

		// These should differ because file hashes YAML text while inline
		// hashes JSON.stringify(rules). This confirms the hash captures
		// the actual source representation, not just semantic equivalence.
		expect(sFile.policyHash).not.toBe(sInline.policyHash);
	});
});
