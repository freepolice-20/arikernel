import { describe, expect, it } from "vitest";
import { generateComplianceReport, type ComplianceReport } from "../src/commands/compliance-report.js";
import { resolve } from "node:path";

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

	it("detects control plane as enabled", () => {
		const report = generateComplianceReport(ROOT);
		expect(report.deployment.controlPlaneEnabled).toBe(true);
	});

	it("reports core protections as enabled", () => {
		const report = generateComplianceReport(ROOT);
		const p = report.protections;

		expect(p.taintTracking).toBe(true);
		expect(p.behavioralRules).toBe(true);
		expect(p.auditLogging).toBe(true);
		expect(p.outputFiltering).toBe(true);
		expect(p.ssrfProtection).toBe(true);
		expect(p.pathTraversal).toBe(true);
		expect(p.capabilityTokens).toBe(true);
		expect(p.quarantine).toBe(true);
	});

	it("reports signed receipts and replay protection when CP exists", () => {
		const report = generateComplianceReport(ROOT);
		expect(report.protections.signedReceipts).toBe(true);
		expect(report.protections.replayProtection).toBe(true);
	});

	it("reports benchmark availability", () => {
		const report = generateComplianceReport(ROOT);
		expect(report.benchmarkSummary.available).toBe(true);
	});
});
