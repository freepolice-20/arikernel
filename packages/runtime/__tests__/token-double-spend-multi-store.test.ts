/**
 * Token double-spend / grant replay across independent stores.
 *
 * This test demonstrates a known limitation: capability grants are protected
 * against replay within a single ITokenStore instance (atomic consume()),
 * but if two sidecar replicas hold independent stores and both receive a
 * copy of the same signed grant, each store will independently accept and
 * consume it. There is no cross-store coordination.
 *
 * This is NOT a bug — it is an explicit design boundary. The mitigation is
 * to back all replicas with a shared ITokenStore implementation (e.g. a
 * shared SQLite file, Redis, or Postgres) so that consume() is globally
 * atomic. The ITokenStore interface already supports this; the built-in
 * TokenStore and SqliteTokenStore are local-only implementations.
 */

import { describe, expect, it } from "vitest";
import type { CapabilityGrant } from "@arikernel/core";
import { TokenStore } from "../src/token-store.js";

function makeGrant(overrides?: Partial<CapabilityGrant>): CapabilityGrant {
	return {
		id: "grant-001",
		principalId: "agent-a",
		capabilityClass: "http.read",
		constraints: {},
		lease: {
			maxCalls: 1,
			callsUsed: 0,
			expiresAt: new Date(Date.now() + 60_000).toISOString(),
		},
		issuedAt: new Date().toISOString(),
		revoked: false,
		...overrides,
	};
}

describe("token double-spend across independent stores", () => {
	it("single store: consume() prevents double-spend", () => {
		const store = new TokenStore();
		const grant = makeGrant();
		store.store(grant);

		// First consumption succeeds
		const first = store.consume("grant-001");
		expect(first.valid).toBe(true);

		// Second consumption on the SAME store is rejected (exhausted)
		const second = store.consume("grant-001");
		expect(second.valid).toBe(false);
		expect(second.reason).toContain("exhausted");
	});

	it("independent stores: same grant can be consumed in both (known limitation)", () => {
		// Simulate two sidecar replicas with independent in-memory stores.
		// Both receive a copy of the same signed grant (e.g. from a shared
		// control plane or via the agent forwarding the grant token).
		const storeA = new TokenStore();
		const storeB = new TokenStore();

		const grant = makeGrant();

		// Both stores receive the same grant
		storeA.store({ ...grant, lease: { ...grant.lease } });
		storeB.store({ ...grant, lease: { ...grant.lease } });

		// Store A consumes the grant — succeeds
		const resultA = storeA.consume("grant-001");
		expect(resultA.valid).toBe(true);

		// Store B consumes the SAME grant — also succeeds (double-spend)
		// This is the replay risk: store B has no knowledge of store A's consumption.
		const resultB = storeB.consume("grant-001");
		expect(resultB.valid).toBe(true);

		// Both stores now show the grant as exhausted locally
		expect(storeA.consume("grant-001").valid).toBe(false);
		expect(storeB.consume("grant-001").valid).toBe(false);

		// NET EFFECT: a maxCalls=1 grant was used twice across replicas.
		// This is the documented limitation that requires a shared backing
		// store for multi-instance deployments.
	});

	it("shared store eliminates double-spend (same instance)", () => {
		// When both replicas use the SAME store instance (or a shared DB),
		// consume() is atomic and the second attempt fails.
		const sharedStore = new TokenStore();
		const grant = makeGrant();
		sharedStore.store(grant);

		// Replica A consumes via the shared store
		const resultA = sharedStore.consume("grant-001");
		expect(resultA.valid).toBe(true);

		// Replica B tries the same grant on the same shared store — rejected
		const resultB = sharedStore.consume("grant-001");
		expect(resultB.valid).toBe(false);
		expect(resultB.reason).toContain("exhausted");
	});

	it("multi-call grant: independent stores allow 2x the intended calls", () => {
		const storeA = new TokenStore();
		const storeB = new TokenStore();

		const grant = makeGrant({
			lease: {
				maxCalls: 3,
				callsUsed: 0,
				expiresAt: new Date(Date.now() + 60_000).toISOString(),
			},
		});

		storeA.store({ ...grant, lease: { ...grant.lease } });
		storeB.store({ ...grant, lease: { ...grant.lease } });

		// Each store allows 3 calls independently = 6 total instead of 3
		let totalConsumed = 0;
		for (let i = 0; i < 3; i++) {
			if (storeA.consume("grant-001").valid) totalConsumed++;
			if (storeB.consume("grant-001").valid) totalConsumed++;
		}

		expect(totalConsumed).toBe(6); // 2x the intended 3 calls
		expect(storeA.consume("grant-001").valid).toBe(false);
		expect(storeB.consume("grant-001").valid).toBe(false);
	});

	it("revocation on one store does not propagate to independent stores", () => {
		const storeA = new TokenStore();
		const storeB = new TokenStore();

		const grant = makeGrant({ lease: { maxCalls: 5, callsUsed: 0, expiresAt: new Date(Date.now() + 60_000).toISOString() } });

		storeA.store({ ...grant, lease: { ...grant.lease } });
		storeB.store({ ...grant, lease: { ...grant.lease } });

		// Revoke on store A
		storeA.revoke("grant-001");
		expect(storeA.consume("grant-001").valid).toBe(false);
		expect(storeA.consume("grant-001").reason).toContain("revoked");

		// Store B is unaware of the revocation — grant still valid
		expect(storeB.consume("grant-001").valid).toBe(true);
	});
});
