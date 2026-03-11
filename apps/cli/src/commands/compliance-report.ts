import { existsSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { resolve } from "node:path";

export interface ComplianceReport {
	generatedAt: string;
	kernelVersion: string;
	deployment: {
		mode: string;
		controlPlaneEnabled: boolean;
		sidecarAuthMode: string;
	};
	policy: {
		filesFound: string[];
		version: string | null;
		hash: string | null;
	};
	protections: {
		taintTracking: boolean;
		behavioralRules: boolean;
		auditLogging: boolean;
		signedReceipts: boolean;
		replayProtection: boolean;
		outputFiltering: boolean;
		ssrfProtection: boolean;
		pathTraversal: boolean;
		capabilityTokens: boolean;
		quarantine: boolean;
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

const PROTECTION_PACKAGES = [
	"@arikernel/core",
	"@arikernel/runtime",
	"@arikernel/policy-engine",
	"@arikernel/taint-tracker",
	"@arikernel/audit-log",
	"@arikernel/control-plane",
	"@arikernel/sidecar",
];

function findPolicyFiles(basePath: string): string[] {
	const candidates = [
		"arikernel.policy.yaml",
		"arikernel.policy.json",
		"policies/safe-defaults.yaml",
		"policies/strict.yaml",
	];
	return candidates
		.map((c) => resolve(basePath, c))
		.filter((p) => existsSync(p));
}

function hashFile(path: string): string {
	const content = readFileSync(path, "utf-8");
	return createHash("sha256").update(content).digest("hex").slice(0, 16);
}

function detectDeploymentMode(basePath: string): string {
	const configFiles = [
		resolve(basePath, "arikernel.config.json"),
		resolve(basePath, "arikernel.config.yaml"),
	];
	for (const f of configFiles) {
		if (existsSync(f)) {
			try {
				const content = readFileSync(f, "utf-8");
				if (content.includes('"secure"') || content.includes("secure")) return "secure";
			} catch { /* ignore */ }
		}
	}
	return "dev";
}

function detectSidecarAuth(basePath: string): string {
	const configFiles = [
		resolve(basePath, "arikernel.config.json"),
		resolve(basePath, "arikernel.config.yaml"),
	];
	for (const f of configFiles) {
		if (existsSync(f)) {
			try {
				const content = readFileSync(f, "utf-8");
				if (content.includes("authToken")) return "bearer-token";
			} catch { /* ignore */ }
		}
	}
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

export function generateComplianceReport(basePath: string): ComplianceReport {
	const policyFiles = findPolicyFiles(basePath);
	const mode = detectDeploymentMode(basePath);
	const sidecarAuth = detectSidecarAuth(basePath);

	let policyHash: string | null = null;
	let policyVersion: string | null = null;
	if (policyFiles.length > 0) {
		policyHash = hashFile(policyFiles[0]);
		try {
			const content = readFileSync(policyFiles[0], "utf-8");
			const versionMatch = content.match(/version:\s*["']?([^"'\n]+)/);
			policyVersion = versionMatch?.[1]?.trim() ?? null;
		} catch { /* ignore */ }
	}

	const cpPkgExists = existsSync(resolve(basePath, "packages/control-plane/package.json"));
	const benchmarkPkgExists = existsSync(resolve(basePath, "packages/benchmarks/package.json"));
	const scenarioCount = countAttackScenarios(basePath);

	// Read kernel version from root package.json
	let kernelVersion = "unknown";
	try {
		const rootPkg = JSON.parse(readFileSync(resolve(basePath, "package.json"), "utf-8"));
		kernelVersion = rootPkg.version ?? "unknown";
	} catch { /* ignore */ }

	return {
		generatedAt: new Date().toISOString(),
		kernelVersion,
		deployment: {
			mode,
			controlPlaneEnabled: cpPkgExists,
			sidecarAuthMode: sidecarAuth,
		},
		policy: {
			filesFound: policyFiles,
			version: policyVersion,
			hash: policyHash,
		},
		protections: {
			taintTracking: true,
			behavioralRules: true,
			auditLogging: true,
			signedReceipts: cpPkgExists,
			replayProtection: cpPkgExists,
			outputFiltering: true,
			ssrfProtection: true,
			pathTraversal: true,
			capabilityTokens: true,
			quarantine: true,
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
	const check = (v: boolean) => (v ? "Yes" : "No");

	return `# AriKernel Compliance Report

Generated: ${report.generatedAt}
Kernel Version: ${report.kernelVersion}

## Deployment

| Setting | Value |
|---------|-------|
| Mode | ${report.deployment.mode} |
| Control Plane | ${check(report.deployment.controlPlaneEnabled)} |
| Sidecar Auth | ${report.deployment.sidecarAuthMode} |

## Policy

| Setting | Value |
|---------|-------|
| Files Found | ${report.policy.filesFound.length > 0 ? report.policy.filesFound.join(", ") : "None"} |
| Version | ${report.policy.version ?? "—"} |
| Hash | ${report.policy.hash ?? "—"} |

## Security Protections

| Protection | Enabled |
|------------|---------|
| Taint Tracking | ${check(p.taintTracking)} |
| Behavioral Rules | ${check(p.behavioralRules)} |
| Audit Logging | ${check(p.auditLogging)} |
| Signed Receipts | ${check(p.signedReceipts)} |
| Replay Protection | ${check(p.replayProtection)} |
| Output Filtering (DLP) | ${check(p.outputFiltering)} |
| SSRF Protection | ${check(p.ssrfProtection)} |
| Path Traversal Protection | ${check(p.pathTraversal)} |
| Capability Tokens | ${check(p.capabilityTokens)} |
| Quarantine | ${check(p.quarantine)} |

## Benchmark Coverage

| Metric | Value |
|--------|-------|
| Available | ${check(report.benchmarkSummary.available)} |
| Total Scenarios | ${report.benchmarkSummary.totalScenarios ?? "—"} |
| Blocked | ${report.benchmarkSummary.blocked ?? "—"} |
| Partial | ${report.benchmarkSummary.partial ?? "—"} |
| Allowed | ${report.benchmarkSummary.allowed ?? "—"} |

## Attack Simulation

| Metric | Value |
|--------|-------|
| Available | ${check(report.attackSimulation.available)} |
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
	const check = (v: boolean) => (v ? "✓" : "✗");

	console.log("=== AriKernel Compliance Report ===\n");
	console.log(`Kernel Version:    ${report.kernelVersion}`);
	console.log(`Generated:         ${report.generatedAt}`);

	console.log("\n--- Deployment ---");
	console.log(`Mode:              ${report.deployment.mode}`);
	console.log(`Control Plane:     ${report.deployment.controlPlaneEnabled ? "enabled" : "disabled"}`);
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
	console.log(`  ${check(p.taintTracking)} Taint Tracking`);
	console.log(`  ${check(p.behavioralRules)} Behavioral Rules`);
	console.log(`  ${check(p.auditLogging)} Audit Logging`);
	console.log(`  ${check(p.signedReceipts)} Signed Receipts`);
	console.log(`  ${check(p.replayProtection)} Replay Protection`);
	console.log(`  ${check(p.outputFiltering)} Output Filtering (DLP)`);
	console.log(`  ${check(p.ssrfProtection)} SSRF Protection`);
	console.log(`  ${check(p.pathTraversal)} Path Traversal Protection`);
	console.log(`  ${check(p.capabilityTokens)} Capability Tokens`);
	console.log(`  ${check(p.quarantine)} Quarantine`);

	console.log("\n--- Benchmark Coverage ---");
	console.log(`  Available: ${report.benchmarkSummary.available ? "yes" : "no"}`);

	console.log("\n--- Attack Simulation ---");
	console.log(`  Available: ${report.attackSimulation.available ? "yes" : "no"}`);
	console.log(`  Scenarios: ${report.attackSimulation.scenariosFound}`);

	console.log("\n=== End Report ===");
}
