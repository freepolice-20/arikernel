import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	type ComplianceReport,
	type ProtectionStatus,
	generateComplianceReport,
} from "../src/commands/compliance-report.js";

const ROOT = resolve(__dirname, "../../..");

describe("Compliance report generator", () => {
	it("generates a report with all required sections", () => {
		const report = generateComplianceReport(ROOT);

		expect(report.generatedAt).toBeTruthy();
		expect(report.kernelVersion).toBeTruthy();
		expect(report.deployment).toBeDefined();
		expect(report.policy).toBeDefined();
		expect(report.protections).toBeDefined();
		expect(report.benchmarkSummary).toBeDefined();
		expect(report.attackSimulation).toBeDefined();
	});

	it("reports always-on protections as enabled", () => {
		const report = generateComplianceReport(ROOT);
		const p = report.protections;

		// These are hardcoded in executor/pipeline code — always active
		expect(p.taintTracking).toBe("enabled");
		expect(p.auditLogging).toBe("enabled");
		expect(p.ssrfProtection).toBe("enabled");
		expect(p.pathTraversal).toBe("enabled");
	});

	it("reports config-dependent protections honestly when no config file exists", () => {
		// Use a temp dir with no config files
		const tmpDir = mkdtempSync(join(tmpdir(), "arikernel-compliance-test-"));
		// Create a minimal package.json so version detection works
		writeFileSync(join(tmpDir, "package.json"), JSON.stringify({ version: "0.0.0-test" }));

		try {
			const report = generateComplianceReport(tmpDir);
			const p = report.protections;

			// Without config, these should NOT be reported as enabled
			expect(p.signedReceipts).toBe("unavailable"); // no CP package
			expect(p.replayProtection).toBe("unavailable");
			expect(p.behavioralRules).toBe("not-configured");
			expect(p.capabilityTokens).toBe("not-configured");
			expect(p.quarantine).toBe("not-configured");
			expect(p.outputFiltering).toBe("not-configured");

			// Control plane should not be reported as configured
			expect(report.deployment.controlPlaneConfigured).toBe(false);
		} finally {
			rmSync(tmpDir, { recursive: true, force: true });
		}
	});

	it("reports signed receipts as not-configured when CP package exists but no signing key in config", () => {
		const tmpDir = mkdtempSync(join(tmpdir(), "arikernel-compliance-test-"));
		writeFileSync(join(tmpDir, "package.json"), JSON.stringify({ version: "0.0.0-test" }));
		// Create a fake control-plane package.json
		const cpDir = join(tmpDir, "packages", "control-plane");
		mkdirSync(cpDir, { recursive: true });
		writeFileSync(join(cpDir, "package.json"), JSON.stringify({ name: "@arikernel/control-plane" }));

		try {
			const report = generateComplianceReport(tmpDir);
			// CP package exists but no config with signingKey
			expect(report.protections.signedReceipts).toBe("not-configured");
			expect(report.protections.replayProtection).toBe("not-configured");
		} finally {
			rmSync(tmpDir, { recursive: true, force: true });
		}
	});

	it("reports signed receipts as configured when signing key is in config", () => {
		const tmpDir = mkdtempSync(join(tmpdir(), "arikernel-compliance-test-"));
		writeFileSync(join(tmpDir, "package.json"), JSON.stringify({ version: "0.0.0-test" }));
		const cpDir = join(tmpDir, "packages", "control-plane");
		mkdirSync(cpDir, { recursive: true });
		writeFileSync(join(cpDir, "package.json"), JSON.stringify({ name: "@arikernel/control-plane" }));
		// Create config with signing key
		writeFileSync(
			join(tmpDir, "arikernel.config.json"),
			JSON.stringify({ signingKey: { algorithm: "hmac-sha256" }, controlPlanePublicKey: "abc" }),
		);

		try {
			const report = generateComplianceReport(tmpDir);
			expect(report.protections.signedReceipts).toBe("configured");
			expect(report.protections.replayProtection).toBe("configured");
			expect(report.deployment.controlPlaneConfigured).toBe(true);
		} finally {
			rmSync(tmpDir, { recursive: true, force: true });
		}
	});

	it("reports behavioral rules as configured when preset or behavioralRules in config", () => {
		const tmpDir = mkdtempSync(join(tmpdir(), "arikernel-compliance-test-"));
		writeFileSync(join(tmpDir, "package.json"), JSON.stringify({ version: "0.0.0-test" }));
		writeFileSync(
			join(tmpDir, "arikernel.config.json"),
			JSON.stringify({ preset: "safe-defaults", behavioralRules: true }),
		);

		try {
			const report = generateComplianceReport(tmpDir);
			expect(report.protections.behavioralRules).toBe("configured");
			expect(report.protections.quarantine).toBe("configured");
		} finally {
			rmSync(tmpDir, { recursive: true, force: true });
		}
	});

	it("reports capability tokens as configured in secure mode", () => {
		const tmpDir = mkdtempSync(join(tmpdir(), "arikernel-compliance-test-"));
		writeFileSync(join(tmpDir, "package.json"), JSON.stringify({ version: "0.0.0-test" }));
		writeFileSync(
			join(tmpDir, "arikernel.config.json"),
			JSON.stringify({ securityMode: "secure" }),
		);

		try {
			const report = generateComplianceReport(tmpDir);
			expect(report.protections.capabilityTokens).toBe("configured");
		} finally {
			rmSync(tmpDir, { recursive: true, force: true });
		}
	});

	it("all protection statuses are valid ProtectionStatus values", () => {
		const report = generateComplianceReport(ROOT);
		const validStatuses: ProtectionStatus[] = ["enabled", "configured", "not-configured", "unavailable"];
		for (const [key, value] of Object.entries(report.protections)) {
			expect(validStatuses).toContain(value);
		}
	});

	it("reports benchmark availability", () => {
		const report = generateComplianceReport(ROOT);
		expect(report.benchmarkSummary.available).toBe(true);
	});
});
