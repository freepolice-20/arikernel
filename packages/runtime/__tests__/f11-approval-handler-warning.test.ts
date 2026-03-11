/**
 * F-11 regression test: require-approval with no handler emits console.warn.
 */

import { unlinkSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it, vi, afterEach, beforeEach } from "vitest";
import { type Firewall, createFirewall } from "../src/index.js";
import { ApprovalRequiredError } from "@arikernel/core";

const auditFiles: string[] = [];

function auditPath(name: string): string {
	const path = resolve(import.meta.dirname, `test-f11-${name}-${Date.now()}.db`);
	auditFiles.push(path);
	return path;
}

afterEach(() => {
	for (const f of auditFiles) {
		try { unlinkSync(f); } catch {}
	}
	auditFiles.length = 0;
});

describe("F-11: approval handler warning", () => {
	it("emits console.warn when require-approval has no handler", async () => {
		const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

		// Create a firewall with a policy that triggers require-approval.
		// We'll use a custom policy engine approach by setting up a firewall
		// and using the hooks to verify the warning fires.
		const fw = createFirewall({
			principal: {
				name: "test-agent",
				capabilities: [
					{ toolClass: "http", actions: ["get"], constraints: { allowedHosts: ["*"] } },
				],
			},
			policies: [
				{
					id: "approval-required-test",
					priority: 1,
					match: { toolClass: "http", action: "get" },
					decision: "require-approval",
					reason: "Manual approval needed",
				},
			],
			auditLog: auditPath("approval-warn"),
			// No onApprovalRequired handler registered
		});

		fw.registerExecutor({
			toolClass: "http",
			async execute(toolCall) {
				return {
					callId: toolCall.id,
					success: true,
					data: null,
					durationMs: 1,
					taintLabels: [],
				};
			},
		});

		const grant = fw.requestCapability("http.read");

		try {
			await expect(
				fw.execute({
					toolClass: "http",
					action: "get",
					parameters: { url: "http://example.com" },
					grantId: grant.grant!.id,
				}),
			).rejects.toThrow(ApprovalRequiredError);

			// Verify warning was emitted
			expect(warnSpy).toHaveBeenCalledWith(
				expect.stringContaining("no onApprovalRequired handler is registered"),
			);
		} finally {
			fw.close();
			warnSpy.mockRestore();
		}
	});

	it("does NOT emit warning when approval handler IS registered", async () => {
		const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

		const fw = createFirewall({
			principal: {
				name: "test-agent",
				capabilities: [
					{ toolClass: "http", actions: ["get"], constraints: { allowedHosts: ["*"] } },
				],
			},
			policies: [
				{
					id: "approval-required-test",
					priority: 1,
					match: { toolClass: "http", action: "get" },
					decision: "require-approval",
					reason: "Manual approval needed",
				},
			],
			auditLog: auditPath("approval-no-warn"),
			hooks: {
				onApprovalRequired: async () => true, // handler exists and approves
			},
		});

		fw.registerExecutor({
			toolClass: "http",
			async execute(toolCall) {
				return {
					callId: toolCall.id,
					success: true,
					data: null,
					durationMs: 1,
					taintLabels: [],
				};
			},
		});

		const grant = fw.requestCapability("http.read");

		try {
			await fw.execute({
				toolClass: "http",
				action: "get",
				parameters: { url: "http://example.com" },
				grantId: grant.grant!.id,
			});

			// No warning should have been emitted
			const approvalWarnings = warnSpy.mock.calls.filter((args) =>
				String(args[0]).includes("onApprovalRequired"),
			);
			expect(approvalWarnings).toHaveLength(0);
		} finally {
			fw.close();
			warnSpy.mockRestore();
		}
	});
});
