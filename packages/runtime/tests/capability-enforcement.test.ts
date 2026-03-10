import { unlinkSync } from "node:fs";
import { resolve } from "node:path";
import { ToolCallDeniedError } from "@arikernel/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Firewall, createFirewall } from "../src/index.js";

const POLICY_PATH = resolve(
	import.meta.dirname,
	"..",
	"..",
	"..",
	"policies",
	"safe-defaults.yaml",
);

function auditPath(name: string): string {
	return resolve(import.meta.dirname, `test-${name}-${Date.now()}.db`);
}

const auditFiles: string[] = [];

function makeFirewall(name: string): Firewall {
	const path = auditPath(name);
	auditFiles.push(path);
	return createFirewall({
		principal: {
			name: "test-agent",
			capabilities: [
				{
					toolClass: "http",
					actions: ["get"],
					constraints: { allowedHosts: ["httpbin.org"] },
				},
				{
					toolClass: "database",
					actions: ["query"],
					constraints: { allowedDatabases: ["analytics"] },
				},
				{
					toolClass: "shell",
					actions: ["exec"],
				},
			],
		},
		policies: POLICY_PATH,
		auditLog: path,
	});
}

afterEach(() => {
	for (const f of auditFiles) {
		try {
			unlinkSync(f);
		} catch {}
	}
	auditFiles.length = 0;
});

describe("Capability Enforcement", () => {
	let fw: Firewall;

	beforeEach(() => {
		fw = makeFirewall("enforce");
	});

	afterEach(() => {
		fw.close();
	});

	it("denies protected tool call with no token", async () => {
		await expect(
			fw.execute({
				toolClass: "database",
				action: "query",
				parameters: { query: "SELECT 1 FROM analytics.test" },
			}),
		).rejects.toThrow(ToolCallDeniedError);

		await expect(
			fw.execute({
				toolClass: "database",
				action: "query",
				parameters: { query: "SELECT 1 FROM analytics.test" },
			}),
		).rejects.toThrow(/Capability token required/);
	});

	it("denies with wrong token class (http token used for database call)", async () => {
		const httpDecision = fw.requestCapability("http.read");
		expect(httpDecision.granted).toBe(true);

		// Single call: verify it throws ToolCallDeniedError with the right message.
		// Cannot call twice with the same grantId — nonce replay detection rejects the second call.
		await expect(
			fw.execute({
				toolClass: "database",
				action: "query",
				parameters: { query: "SELECT 1 FROM analytics.test" },
				grantId: httpDecision.grant?.id,
			}),
		).rejects.toThrow(/cannot be used for tool class/);
	});

	it("denies with expired token", async () => {
		const decision = fw.requestCapability("database.read");
		expect(decision.granted).toBe(true);

		// Manually expire the grant by mutating the lease
		const grant = decision.grant!;
		grant.lease.expiresAt = new Date(Date.now() - 1000).toISOString();

		// Single call: verify it throws with "expired" message.
		// Cannot call twice with the same grantId — nonce replay detection rejects the second call.
		await expect(
			fw.execute({
				toolClass: "database",
				action: "query",
				parameters: { query: "SELECT 1 FROM analytics.test" },
				grantId: grant.id,
			}),
		).rejects.toThrow(/expired/);
	});

	it("denies issuance for tainted context, then denies tool call without token", async () => {
		const webTaint = [
			{
				source: "web" as const,
				origin: "evil.com",
				confidence: 1.0,
				addedAt: new Date().toISOString(),
			},
		];

		// Issuance denied due to taint
		const issuance = fw.requestCapability("database.read", {
			taintLabels: webTaint,
		});
		expect(issuance.granted).toBe(false);
		expect(issuance.reason).toContain("untrusted taint");

		// Without a token, the tool call must also be denied
		await expect(
			fw.execute({
				toolClass: "database",
				action: "query",
				parameters: { query: "SELECT 1 FROM analytics.test" },
				taintLabels: webTaint,
			}),
		).rejects.toThrow(ToolCallDeniedError);

		await expect(
			fw.execute({
				toolClass: "database",
				action: "query",
				parameters: { query: "SELECT 1 FROM analytics.test" },
				taintLabels: webTaint,
			}),
		).rejects.toThrow(/Capability token required/);
	});

	it("allows protected tool call with valid token", async () => {
		const decision = fw.requestCapability("database.read");
		expect(decision.granted).toBe(true);

		// Database executor is a stub that may throw, so we check
		// that it does NOT throw ToolCallDeniedError (it gets past enforcement)
		try {
			await fw.execute({
				toolClass: "database",
				action: "query",
				parameters: { query: "SELECT 1 FROM analytics.test" },
				grantId: decision.grant?.id,
			});
		} catch (err) {
			// If it throws, it must NOT be a denied error — it should be
			// an executor error (database stub) or similar
			expect(err).not.toBeInstanceOf(ToolCallDeniedError);
		}
	});

	it("denies when lease usage is exhausted", async () => {
		const decision = fw.requestCapability("database.read");
		expect(decision.granted).toBe(true);

		// Exhaust the lease by setting callsUsed to maxCalls
		const grant = decision.grant!;
		grant.lease.callsUsed = grant.lease.maxCalls;

		await expect(
			fw.execute({
				toolClass: "database",
				action: "query",
				parameters: { query: "SELECT 1 FROM analytics.test" },
				grantId: grant.id,
			}),
		).rejects.toThrow(/exhausted/);
	});

	it("denies when grant is revoked", async () => {
		const decision = fw.requestCapability("database.read");
		expect(decision.granted).toBe(true);

		fw.revokeGrant(decision.grant?.id);

		await expect(
			fw.execute({
				toolClass: "database",
				action: "query",
				parameters: { query: "SELECT 1 FROM analytics.test" },
				grantId: decision.grant?.id,
			}),
		).rejects.toThrow(/revoked/);
	});

	it("audit logs denied attempts for missing tokens", async () => {
		try {
			await fw.execute({
				toolClass: "database",
				action: "query",
				parameters: { query: "SELECT 1 FROM analytics.test" },
			});
		} catch {}

		const events = fw.getEvents();
		expect(events.length).toBeGreaterThanOrEqual(1);

		const lastEvent = events[events.length - 1];
		expect(lastEvent.decision.verdict).toBe("deny");
		expect(lastEvent.decision.reason).toContain("Capability token required");
	});
});
