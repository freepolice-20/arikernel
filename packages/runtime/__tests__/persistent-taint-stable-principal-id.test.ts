/**
 * Verifies that persistent taint is keyed by stable principal identity (name),
 * not the random per-run principal.id. Two Firewall instances created for the
 * same principal.name must share persistent state; different names must not.
 */

import { unlinkSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createFirewall } from "../src/index.js";
import type { FirewallOptions } from "../src/index.js";

const auditFiles: string[] = [];

function auditPath(label: string): string {
	const p = resolve(import.meta.dirname, `test-stable-pid-${label}-${Date.now()}.db`);
	auditFiles.push(p);
	return p;
}

afterEach(() => {
	for (const f of auditFiles) {
		try {
			unlinkSync(f);
		} catch {}
	}
	auditFiles.length = 0;
});

function makeOptions(principalName: string, dbPath: string): FirewallOptions {
	return {
		principal: {
			name: principalName,
			capabilities: [{ toolClass: "http" }, { toolClass: "file" }],
		},
		policies: [
			{
				id: "allow-file-read",
				name: "Allow file read",
				priority: 10,
				match: { toolClass: "file", action: "read" },
				decision: "allow" as const,
			},
		],
		auditLog: dbPath,
		persistentTaint: { enabled: true, retentionWindowMs: 60_000 },
	};
}

describe("Persistent taint keyed by stable principal name", () => {
	it("Run 2 inherits sensitiveReadObserved from Run 1 for the same principal", () => {
		const db = auditPath("same-principal");

		// Run 1: record a sensitive read
		const fw1 = createFirewall(makeOptions("agent-alpha", db));
		fw1.registerExecutor({
			toolClass: "file",
			async execute(tc) {
				return { callId: tc.id, success: true, data: "key", durationMs: 1, taintLabels: [] };
			},
		});
		// Directly record via the registry (simulates a completed sensitive read)
		fw1.persistentTaintRegistry?.recordSensitiveRead("/home/.ssh/id_rsa");
		expect(fw1.sensitiveReadObserved).toBe(false); // not set via pipeline, just persisted
		fw1.close();

		// Run 2: same principal name, fresh Firewall instance, same DB
		const fw2 = createFirewall(makeOptions("agent-alpha", db));
		// The constructor should have restored the sticky flag
		expect(fw2.sensitiveReadObserved).toBe(true);
		fw2.close();
	});

	it("Run 2 inherits tainted flag from Run 1", () => {
		const db = auditPath("multi-flags");

		const fw1 = createFirewall(makeOptions("agent-beta", db));
		fw1.persistentTaintRegistry?.recordTaintObserved("web");
		fw1.close();

		const fw2 = createFirewall(makeOptions("agent-beta", db));
		expect(fw2.taintState.tainted).toBe(true);
		expect(fw2.taintState.sources).toContain("web");
		fw2.close();
	});

	it("different principal names are isolated — principal B does not see A's state", () => {
		const db = auditPath("isolation");

		// Principal A records sensitive read
		const fwA = createFirewall(makeOptions("principal-A", db));
		fwA.persistentTaintRegistry?.recordSensitiveRead("/etc/shadow");
		fwA.close();

		// Principal B on the same DB should NOT inherit A's state
		const fwB = createFirewall(makeOptions("principal-B", db));
		expect(fwB.sensitiveReadObserved).toBe(false);
		fwB.close();

		// Principal A on a new run should still see it
		const fwA2 = createFirewall(makeOptions("principal-A", db));
		expect(fwA2.sensitiveReadObserved).toBe(true);
		fwA2.close();
	});

	it("persistent taint survives multiple restarts for the same principal", () => {
		const db = auditPath("multi-restart");

		// Run 1: record sensitive read
		const fw1 = createFirewall(makeOptions("agent-gamma", db));
		fw1.persistentTaintRegistry?.recordSensitiveRead("/home/.ssh/id_rsa");
		fw1.close();

		// Run 2: inherits and records more
		const fw2 = createFirewall(makeOptions("agent-gamma", db));
		expect(fw2.sensitiveReadObserved).toBe(true);
		fw2.persistentTaintRegistry?.recordTaintObserved("web");
		fw2.close();

		// Run 3: sees both flags
		const fw3 = createFirewall(makeOptions("agent-gamma", db));
		expect(fw3.sensitiveReadObserved).toBe(true);
		expect(fw3.taintState.tainted).toBe(true);
		fw3.close();
	});
});
