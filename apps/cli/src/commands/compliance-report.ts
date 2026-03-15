import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

/**
 * Protection status reflects actual enforcement state, not just package presence.
 *
 * - "enabled"        — always-on code path, no configuration needed
 * - "configured"     — config detected that activates this protection
 * - "not-configured" — protection requires configuration that was not found
 * - "unavailable"    — required package/infrastructure not present
 */
export type ProtectionStatus = "enabled" | "configured" | "not-configured" | "unavailable";

export interface ComplianceReport {
	generatedAt: string;
	kernelVersion: string;
	deployment: {
		mode: string;
		controlPlaneConfigured: boolean;
		sidecarAuthMode: string;
	};
	policy: {
		filesFound: string[];
		version: string | null;
		hash: string | null;
	};
	protections: {
		taintTracking: ProtectionStatus;
		behavioralRules: ProtectionStatus;
		auditLogging: ProtectionStatus;
		signedReceipts: ProtectionStatus;
		replayProtection: ProtectionStatus;
		outputFiltering: ProtectionStatus;
		ssrfProtection: ProtectionStatus;
		pathTraversal: ProtectionStatus;
		capabilityTokens: ProtectionStatus;
		quarantine: ProtectionStatus;
	};
	benchmarkSummary: {
		available: boolean;
		totalScenarios: number | null;
		blocked: number | null;
		partial: number | null;
		allowed: number | null;
	};
	attackSimulation: {
		available: boolean;
		scenariosFound: number;
	};
}

function findPolicyFiles(basePath: string): string[] {
	const candidates = [
		"arikernel.policy.yaml",
		"arikernel.policy.json",
		"policies/safe-defaults.yaml",
		"policies/strict.yaml",
	];
	return candidates.map((c) => resolve(basePath, c)).filter((p) => existsSync(p));
}

function hashFile(path: string): string {
	const content = readFileSync(path, "utf-8");
	return createHash("sha256").update(content).digest("hex").slice(0, 16);
}

/** Read config file content, returning null if not found. */
function readConfigContent(basePath: string): string | null {
	const configFiles = [
		resolve(basePath, "arikernel.config.json"),
		resolve(basePath, "arikernel.config.yaml"),
	];
	for (const f of configFiles) {
		if (existsSync(f)) {
			try {
				return readFileSync(f, "utf-8");
			} catch {
				/* ignore */
			}
		}
	}
	return null;
}

function detectDeploymentMode(configContent: string | null): string {
	if (configContent) {
		if (configContent.includes('"secure"') || configContent.includes("secure")) return "secure";
	}
	return "dev";
}

function detectSidecarAuth(configContent: string | null): string {
	if (configContent && configContent.includes("authToken")) return "bearer-token";
	return "none (dev mode)";
}

function countAttackScenarios(basePath: string): number {
	const scenarioDir = resolve(basePath, "packages/attack-sim/scenarios");
	if (!existsSync(scenarioDir)) return 0;
	try {
		const { readdirSync } = require("node:fs");
		return (readdirSync(scenarioDir) as string[]).filter(
			(f: string) => f.endsWith(".yaml") || f.endsWith(".yml"),
		).length;
	} catch {
		return 0;
	}
}

/**
 * Detect whether the control plane is actually configured for use,
 * not just whether the package exists in the monorepo.
 */
function detectControlPlaneConfigured(configContent: string | null): boolean {
	if (!configContent) return false;
	// Look for actual CP configuration: signing key, control plane URL, or public key
	return (
		configContent.includes("signingKey") ||
		configContent.includes("controlPlaneUrl") ||
		configContent.includes("controlPlanePublicKey")
	);
}

/**
 * Detect whether signed receipt verification is configured.
 * Requires both a signing key (CP side) and public key (sidecar side),
 * or at minimum one of them in the config.
 */
function detectSignedReceipts(configContent: string | null): ProtectionStatus {
	if (!configContent) return "not-configured";
	const hasSigningKey = configContent.includes("signingKey");
	const hasPublicKey = configContent.includes("controlPlanePublicKey");
	if (hasSigningKey && hasPublicKey) return "configured";
	if (hasSigningKey || hasPublicKey) return "configured";
	return "not-configured";
}

/**
 * Detect whether behavioral rules are configured.
 * Requires runStatePolicy with behavioralRules enabled.
 */
function detectBehavioralRules(configContent: string | null): ProtectionStatus {
	if (!configContent) return "not-configured";
	if (configContent.includes("behavioralRules")) return "configured";
	// Presets may enable behavioral rules implicitly
	if (configContent.includes("preset")) return "configured";
	return "not-configured";
}

/**
 * Detect capability token enforcement mode.
 * Requires securityMode: "secure" or a signingKey.
 */
function detectCapabilityTokens(configContent: string | null): ProtectionStatus {
	if (!configContent) return "not-configured";
	if (
		configContent.includes('"secure"') ||
		configContent.includes("securityMode: secure") ||
		configContent.includes("signingKey")
	) {
		return "configured";
	}
	return "not-configured";
}

export function generateComplianceReport(basePath: string): ComplianceReport {
	const policyFiles = findPolicyFiles(basePath);
	const configContent = readConfigContent(basePath);
	const mode = detectDeploymentMode(configContent);
	const sidecarAuth = detectSidecarAuth(configContent);

	let policyHash: string | null = null;
	let policyVersion: string | null = null;
	if (policyFiles.length > 0) {
		policyHash = hashFile(policyFiles[0]);
		try {
			const content = readFileSync(policyFiles[0], "utf-8");
			const versionMatch = content.match(/version:\s*["']?([^"'\n]+)/);
			policyVersion = versionMatch?.[1]?.trim() ?? null;
		} catch {
			/* ignore */
		}
	}

	const cpPkgExists = existsSync(resolve(basePath, "packages/control-plane/package.json"));
	const benchmarkPkgExists = existsSync(resolve(basePath, "packages/benchmarks/package.json"));
	const scenarioCount = countAttackScenarios(basePath);

	// Read kernel version from root package.json
	let kernelVersion = "unknown";
	try {
		const rootPkg = JSON.parse(readFileSync(resolve(basePath, "package.json"), "utf-8"));
		kernelVersion = rootPkg.version ?? "unknown";
	} catch {
		/* ignore */
	}

	// Signed receipts and replay protection require both CP package and config
	const signedReceiptsStatus: ProtectionStatus = cpPkgExists
		? detectSignedReceipts(configContent)
		: "unavailable";

	return {
		generatedAt: new Date().toISOString(),
		kernelVersion,
		deployment: {
			mode,
			controlPlaneConfigured: detectControlPlaneConfigured(configContent),
			sidecarAuthMode: sidecarAuth,
		},
		policy: {
			filesFound: policyFiles,
			version: policyVersion,
			hash: policyHash,
		},
		protections: {
			// Always-on: these are hardcoded in the executor/pipeline code paths
			taintTracking: "enabled",
			auditLogging: "enabled",
			ssrfProtection: "enabled",
			pathTraversal: "enabled",

			// Config-dependent: require explicit setup
			behavioralRules: detectBehavioralRules(configContent),
			signedReceipts: signedReceiptsStatus,
			replayProtection: signedReceiptsStatus, // tied to signed receipts
			outputFiltering: "not-configured", // requires hooks.onOutputFilter registration
			capabilityTokens: detectCapabilityTokens(configContent),
			quarantine: detectBehavioralRules(configContent), // quarantine requires behavioral rules
		},
		benchmarkSummary: {
			available: benchmarkPkgExists,
			totalScenarios: null,
			blocked: null,
			partial: null,
			allowed: null,
		},
		attackSimulation: {
			available: scenarioCount > 0,
			scenariosFound: scenarioCount,
		},
	};
}

function formatMarkdown(report: ComplianceReport): string {
	const p = report.protections;
	const status = (v: ProtectionStatus) => {
		switch (v) {
			case "enabled":
				return "Enabled (always-on)";
			case "configured":
				return "Configured";
			case "not-configured":
				return "Not configured";
			case "unavailable":
				return "Unavailable";
		}
	};

	return `# AriKernel Compliance Report

Generated: ${report.generatedAt}
Kernel Version: ${report.kernelVersion}

## Deployment

| Setting | Value |
|---------|-------|
| Mode | ${report.deployment.mode} |
| Control Plane | ${report.deployment.controlPlaneConfigured ? "Configured" : "Not configured"} |
| Sidecar Auth | ${report.deployment.sidecarAuthMode} |

## Policy

| Setting | Value |
|---------|-------|
| Files Found | ${report.policy.filesFound.length > 0 ? report.policy.filesFound.join(", ") : "None"} |
| Version | ${report.policy.version ?? "—"} |
| Hash | ${report.policy.hash ?? "—"} |

## Security Protections

| Protection | Status |
|------------|--------|
| Taint Tracking | ${status(p.taintTracking)} |
| Behavioral Rules | ${status(p.behavioralRules)} |
| Audit Logging | ${status(p.auditLogging)} |
| Signed Receipts | ${status(p.signedReceipts)} |
| Replay Protection | ${status(p.replayProtection)} |
| Output Filtering (DLP) | ${status(p.outputFiltering)} |
| SSRF Protection | ${status(p.ssrfProtection)} |
| Path Traversal Protection | ${status(p.pathTraversal)} |
| Capability Tokens | ${status(p.capabilityTokens)} |
| Quarantine | ${status(p.quarantine)} |

> **Note:** Protections marked "Enabled (always-on)" are hardcoded in executor/pipeline code.
> Protections marked "Configured" were detected in your deployment configuration.
> "Not configured" means the feature requires explicit setup. See deployment docs.

## Benchmark Coverage

| Metric | Value |
|--------|-------|
| Available | ${report.benchmarkSummary.available ? "Yes" : "No"} |
| Total Scenarios | ${report.benchmarkSummary.totalScenarios ?? "—"} |
| Blocked | ${report.benchmarkSummary.blocked ?? "—"} |
| Partial | ${report.benchmarkSummary.partial ?? "—"} |
| Allowed | ${report.benchmarkSummary.allowed ?? "—"} |

## Attack Simulation

| Metric | Value |
|--------|-------|
| Available | ${report.attackSimulation.available ? "Yes" : "No"} |
| Scenarios Found | ${report.attackSimulation.scenariosFound} |
`;
}

export function runComplianceReport(options: {
	json?: boolean;
	markdown?: boolean;
}): void {
	const basePath = process.cwd();
	const report = generateComplianceReport(basePath);

	if (options.json) {
		console.log(JSON.stringify(report, null, 2));
		return;
	}

	if (options.markdown) {
		console.log(formatMarkdown(report));
		return;
	}

	// Default: human-readable summary
	const p = report.protections;
	const icon = (v: ProtectionStatus) => {
		switch (v) {
			case "enabled":
				return "✓";
			case "configured":
				return "✓";
			case "not-configured":
				return "○";
			case "unavailable":
				return "✗";
		}
	};
	const label = (v: ProtectionStatus) => {
		switch (v) {
			case "enabled":
				return "(always-on)";
			case "configured":
				return "(configured)";
			case "not-configured":
				return "(not configured)";
			case "unavailable":
				return "(unavailable)";
		}
	};

	console.log("=== AriKernel Compliance Report ===\n");
	console.log(`Kernel Version:    ${report.kernelVersion}`);
	console.log(`Generated:         ${report.generatedAt}`);

	console.log("\n--- Deployment ---");
	console.log(`Mode:              ${report.deployment.mode}`);
	console.log(
		`Control Plane:     ${report.deployment.controlPlaneConfigured ? "configured" : "not configured"}`,
	);
	console.log(`Sidecar Auth:      ${report.deployment.sidecarAuthMode}`);

	console.log("\n--- Policy ---");
	if (report.policy.filesFound.length > 0) {
		for (const f of report.policy.filesFound) {
			console.log(`  File: ${f}`);
		}
		if (report.policy.version) console.log(`  Version: ${report.policy.version}`);
		if (report.policy.hash) console.log(`  Hash:    ${report.policy.hash}`);
	} else {
		console.log("  No policy files found");
	}

	console.log("\n--- Security Protections ---");
	console.log(`  ${icon(p.taintTracking)} Taint Tracking ${label(p.taintTracking)}`);
	console.log(`  ${icon(p.behavioralRules)} Behavioral Rules ${label(p.behavioralRules)}`);
	console.log(`  ${icon(p.auditLogging)} Audit Logging ${label(p.auditLogging)}`);
	console.log(`  ${icon(p.signedReceipts)} Signed Receipts ${label(p.signedReceipts)}`);
	console.log(`  ${icon(p.replayProtection)} Replay Protection ${label(p.replayProtection)}`);
	console.log(`  ${icon(p.outputFiltering)} Output Filtering (DLP) ${label(p.outputFiltering)}`);
	console.log(`  ${icon(p.ssrfProtection)} SSRF Protection ${label(p.ssrfProtection)}`);
	console.log(`  ${icon(p.pathTraversal)} Path Traversal Protection ${label(p.pathTraversal)}`);
	console.log(`  ${icon(p.capabilityTokens)} Capability Tokens ${label(p.capabilityTokens)}`);
	console.log(`  ${icon(p.quarantine)} Quarantine ${label(p.quarantine)}`);

	console.log("\n--- Benchmark Coverage ---");
	console.log(`  Available: ${report.benchmarkSummary.available ? "yes" : "no"}`);

	console.log("\n--- Attack Simulation ---");
	console.log(`  Available: ${report.attackSimulation.available ? "yes" : "no"}`);
	console.log(`  Scenarios: ${report.attackSimulation.scenariosFound}`);

	console.log("\n=== End Report ===");
}
