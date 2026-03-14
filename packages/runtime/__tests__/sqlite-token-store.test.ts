import { mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { SqliteTokenStore } from "../src/sqlite-token-store.js";
import type { CapabilityGrant } from "@arikernel/core";

function makeGrant(overrides?: Partial<CapabilityGrant>): CapabilityGrant {
	return {
		id: randomUUID(),
		principalId: "test-agent",
		capabilityClass: "http.read",
		constraints: {},
		revoked: false,
		lease: {
			issuedAt: new Date().toISOString(),
			expiresAt: new Date(Date.now() + 300_000).toISOString(), // 5 min
			maxCalls: 10,
			callsUsed: 0,
		},
		...overrides,
	};
}

describe("SqliteTokenStore", () => {
	let testDir: string;
	let dbPath: string;
	let openStores: SqliteTokenStore[];

	beforeEach(() => {
		testDir = join(tmpdir(), `arikernel-test-${randomUUID()}`);
		mkdirSync(testDir, { recursive: true });
		dbPath = join(testDir, "tokens.db");
		openStores = [];
	});

	afterEach(() => {
		// Close all open stores before deleting (Windows EBUSY)
		for (const s of openStores) {
			try { s.close(); } catch {}
		}
		rmSync(testDir, { recursive: true, force: true });
	});

	function createStore(opts?: { maxSize?: number }): SqliteTokenStore {
		const s = new SqliteTokenStore(dbPath, opts);
		openStores.push(s);
		return s;
	}

	it("stores and retrieves a grant", () => {
		const store = createStore();
		const grant = makeGrant();
		store.store(grant);

		const retrieved = store.get(grant.id);
		expect(retrieved).not.toBeNull();
		expect(retrieved!.id).toBe(grant.id);
		expect(retrieved!.capabilityClass).toBe("http.read");
	});

	it("persists grants across store instances (survives restart)", () => {
		const grant = makeGrant();

		// Store in first instance
		const store1 = createStore();
		store1.store(grant, "sig123", "ed25519");
		store1.close();

		// Reopen — simulates sidecar restart
		const store2 = createStore();
		const retrieved = store2.get(grant.id);
		expect(retrieved).not.toBeNull();
		expect(retrieved!.id).toBe(grant.id);

		const storedToken = store2.getStoredToken(grant.id);
		expect(storedToken).not.toBeNull();
		expect(storedToken!.signature).toBe("sig123");
		expect(storedToken!.algorithm).toBe("ed25519");
	});

	it("validates active grants correctly", () => {
		const store = createStore();
		const grant = makeGrant();
		store.store(grant);

		expect(store.validate(grant.id)).toEqual({ valid: true });
	});

	it("validates expired grants correctly", () => {
		const store = createStore();
		const grant = makeGrant({
			lease: {
				issuedAt: new Date(Date.now() - 600_000).toISOString(),
				expiresAt: new Date(Date.now() - 1).toISOString(),
				maxCalls: 10,
				callsUsed: 0,
			},
		});
		store.store(grant);

		const result = store.validate(grant.id);
		expect(result.valid).toBe(false);
		expect(result.reason).toContain("expired");
	});

	it("validates revoked grants correctly", () => {
		const store = createStore();
		const grant = makeGrant();
		store.store(grant);

		store.revoke(grant.id);
		const result = store.validate(grant.id);
		expect(result.valid).toBe(false);
		expect(result.reason).toContain("revoked");
	});

	it("consume() increments callsUsed atomically", () => {
		const store = createStore();
		const grant = makeGrant({ lease: { ...makeGrant().lease, maxCalls: 3, callsUsed: 0 } });
		store.store(grant);

		expect(store.consume(grant.id)).toEqual({ valid: true });
		expect(store.consume(grant.id)).toEqual({ valid: true });
		expect(store.consume(grant.id)).toEqual({ valid: true });

		const exhausted = store.consume(grant.id);
		expect(exhausted.valid).toBe(false);
		expect(exhausted.reason).toContain("exhausted");
	});

	it("enforces maxSize with LRU eviction", () => {
		const store = createStore({ maxSize: 3 });

		const g1 = makeGrant();
		const g2 = makeGrant();
		const g3 = makeGrant();

		store.store(g1);
		store.store(g2);
		store.store(g3);

		// Verify all 3 fit within maxSize
		expect(store.get(g1.id)).not.toBeNull();
		expect(store.get(g2.id)).not.toBeNull();
		expect(store.get(g3.id)).not.toBeNull();

		// Adding a 4th should evict one (the LRU entry)
		const g4 = makeGrant();
		store.store(g4);

		// Exactly one of the original 3 should have been evicted
		const surviving = [g1, g2, g3].filter((g) => store.get(g.id) !== null);
		expect(surviving).toHaveLength(2);
		// g4 must still be present
		expect(store.get(g4.id)).not.toBeNull();
	});

	it("activeGrants() returns only valid grants for a principal", () => {
		const store = createStore();

		const active = makeGrant({ principalId: "agent-a" });
		const expired = makeGrant({
			principalId: "agent-a",
			lease: {
				issuedAt: new Date(Date.now() - 600_000).toISOString(),
				expiresAt: new Date(Date.now() - 1).toISOString(),
				maxCalls: 10,
				callsUsed: 0,
			},
		});
		const otherPrincipal = makeGrant({ principalId: "agent-b" });

		store.store(active);
		store.store(expired);
		store.store(otherPrincipal);

		const grants = store.activeGrants("agent-a");
		expect(grants).toHaveLength(1);
		expect(grants[0].id).toBe(active.id);
	});

	it("evictExpired() removes expired, exhausted, and revoked entries", () => {
		const store = createStore();

		const active = makeGrant();
		const expired = makeGrant({
			lease: {
				issuedAt: new Date(Date.now() - 600_000).toISOString(),
				expiresAt: new Date(Date.now() - 1).toISOString(),
				maxCalls: 10,
				callsUsed: 0,
			},
		});
		const exhausted = makeGrant({
			lease: {
				issuedAt: new Date().toISOString(),
				expiresAt: new Date(Date.now() + 300_000).toISOString(),
				maxCalls: 5,
				callsUsed: 5,
			},
		});

		store.store(active);
		store.store(expired);
		store.store(exhausted);

		const removed = store.evictExpired();
		expect(removed).toBe(2); // both expired and exhausted

		expect(store.get(active.id)).not.toBeNull();
		expect(store.get(expired.id)).toBeNull();
		expect(store.get(exhausted.id)).toBeNull();
	});

	it("get() returns null for nonexistent grant", () => {
		const store = createStore();
		expect(store.get("nonexistent")).toBeNull();
		expect(store.getStoredToken("nonexistent")).toBeNull();
	});
});
