#!/usr/bin/env node
import { DEFAULT_HOST, DEFAULT_PORT } from "@arikernel/sidecar";
import { defineCommand, runMain } from "citty";
import { runAttackList, runAttackSimulate } from "./commands/attack.js";
import { runBenchmarkSecurity } from "./commands/benchmark-security.js";
import { runBenchmark } from "./commands/benchmark.js";
import { runComplianceReport } from "./commands/compliance-report.js";
import { runExportAudit } from "./commands/control-plane.js";
import { runInit } from "./commands/init.js";
import { runPolicyTestCommand } from "./commands/policy-test.js";
import { runPolicyList, runPolicyShow, runPolicyValidate } from "./commands/policy.js";
import { runReplayTrace } from "./commands/replay-trace.js";
import { runReplay } from "./commands/replay.js";
import { runAgent } from "./commands/run.js";
import { runSidecar } from "./commands/sidecar.js";
import { runSimulate } from "./commands/simulate.js";
import { runTrace } from "./commands/trace.js";
import { runVerifyReceipt } from "./commands/verify-receipt.js";

const init = defineCommand({
	meta: { name: "init", description: "Initialize arikernel config" },
	run: () => runInit(),
});

const policyValidate = defineCommand({
	meta: { name: "validate", description: "Validate a policy file" },
	args: {
		file: { type: "positional", description: "Policy file path", required: true },
	},
	run: ({ args }) => runPolicyValidate(args.file),
});

const policyList = defineCommand({
	meta: { name: "list", description: "List available security presets" },
	run: () => runPolicyList(),
});

const policyShow = defineCommand({
	meta: { name: "show", description: "Show details of a security preset" },
	args: {
		name: {
			type: "positional",
			description: "Preset name (e.g. safe, strict, research)",
			required: true,
		},
	},
	run: ({ args }) => runPolicyShow(args.name),
});

const policy = defineCommand({
	meta: { name: "policy", description: "Policy and preset management" },
	subCommands: { validate: policyValidate, list: policyList, show: policyShow },
});

const replay = defineCommand({
	meta: { name: "replay", description: "Replay a run from audit log" },
	args: {
		db: { type: "string", description: "Audit database path", default: "./arikernel-audit.db" },
		latest: { type: "boolean", description: "Replay the most recent run", default: false },
		verbose: {
			type: "boolean",
			description: "Show params, rule, and hash for each event",
			default: false,
		},
		step: { type: "boolean", description: "Step through events with delay", default: false },
		runId: {
			type: "positional",
			description: "Run ID to replay (omit with --latest)",
			required: false,
		},
	},
	run: ({ args }) =>
		runReplay(args.db, args.runId, {
			latest: args.latest,
			verbose: args.verbose,
			step: args.step,
		}),
});

const run = defineCommand({
	meta: { name: "run", description: "Start firewall in run mode" },
	args: {
		policy: { type: "string", description: "Policy file path", default: "./arikernel.policy.yaml" },
		auditLog: { type: "string", description: "Audit log path", default: "./arikernel-audit.db" },
	},
	run: ({ args }) => runAgent(args.policy, args.auditLog),
});

const simulate = defineCommand({
	meta: { name: "simulate", description: "Run attack simulations" },
	args: {
		policy: {
			type: "string",
			description: "Policy file path (uses built-in safe defaults if omitted)",
		},
		db: { type: "string", description: "Audit database path", default: "./arikernel-audit.db" },
		attackType: {
			type: "positional",
			description: "Attack type: prompt-injection, data-exfiltration, tool-escalation",
			required: false,
		},
	},
	run: ({ args }) => runSimulate(args.policy, args.attackType, args.db),
});

const trace = defineCommand({
	meta: { name: "trace", description: "Display security execution trace" },
	args: {
		db: { type: "string", description: "Audit database path", default: "./arikernel-audit.db" },
		latest: { type: "boolean", description: "Trace the most recent run", default: false },
		runId: {
			type: "positional",
			description: "Run ID to trace (omit with --latest)",
			required: false,
		},
	},
	run: ({ args }) => runTrace(args.db, args.runId, { latest: args.latest }),
});

const sidecar = defineCommand({
	meta: { name: "sidecar", description: "Start AriKernel as a sidecar enforcement proxy" },
	args: {
		policy: { type: "string", description: "Policy file path", default: "./arikernel.policy.yaml" },
		port: {
			type: "string",
			description: "TCP port to listen on (default: 8787)",
			default: String(DEFAULT_PORT),
		},
		host: {
			type: "string",
			description:
				"Host/IP to bind to (default: 127.0.0.1). Use 0.0.0.0 to expose on all interfaces.",
			default: DEFAULT_HOST,
		},
		auditLog: { type: "string", description: "Audit log path", default: "./sidecar-audit.db" },
		authToken: { type: "string", description: "Bearer token for authenticating requests" },
		tlsCert: { type: "string", description: "Path to TLS certificate file (PEM). Enables HTTPS." },
		tlsKey: { type: "string", description: "Path to TLS private key file (PEM). Required with --tls-cert." },
	},
	run: ({ args }) =>
		runSidecar({
			policy: args.policy,
			port: Number(args.port),
			host: args.host,
			auditLog: args.auditLog,
			authToken: args.authToken,
			tlsCert: args.tlsCert,
			tlsKey: args.tlsKey,
		}),
});

const benchmarkRun = defineCommand({
	meta: { name: "run", description: "Run full benchmark suite with detailed output" },
	args: {
		resultsDir: {
			type: "string",
			description: "Output directory for results",
		},
	},
	run: ({ args }) => runBenchmark(args.resultsDir),
});

const benchmarkSecurity = defineCommand({
	meta: { name: "security", description: "Run security validation benchmark for release checks" },
	args: {
		resultsDir: {
			type: "string",
			description: "Output directory for results",
		},
	},
	run: ({ args }) => runBenchmarkSecurity(args.resultsDir),
});

const benchmarkCmd = defineCommand({
	meta: { name: "benchmark", description: "Run reproducible attack benchmark suite" },
	subCommands: { run: benchmarkRun, security: benchmarkSecurity },
});

const replayTrace = defineCommand({
	meta: { name: "replay-trace", description: "Replay a JSON trace file through the kernel" },
	args: {
		tracePath: { type: "positional", description: "Path to the trace JSON file", required: true },
		policy: { type: "string", description: "Policy file override for what-if analysis" },
		preset: { type: "string", description: "Preset override for what-if analysis" },
		json: { type: "boolean", description: "Output raw JSON summary", default: false },
		verbose: { type: "boolean", description: "Show event-by-event comparison", default: false },
		timeline: {
			type: "boolean",
			description: "Show attack timeline visualization",
			default: false,
		},
		summary: {
			type: "boolean",
			description: "Show concise trace summary with counters",
			default: false,
		},
		graph: {
			type: "boolean",
			description: "Show ASCII attack sequence graph",
			default: false,
		},
	},
	run: ({ args }) =>
		runReplayTrace(args.tracePath, {
			policy: args.policy,
			preset: args.preset,
			json: args.json,
			verbose: args.verbose,
			timeline: args.timeline,
			summary: args.summary,
			graph: args.graph,
		}),
});

const attackSimulate = defineCommand({
	meta: { name: "simulate", description: "Simulate a YAML attack scenario through the kernel" },
	args: {
		scenario: {
			type: "positional",
			description: "Path to a YAML scenario file",
			required: true,
		},
		policy: { type: "string", description: "Policy file path" },
	},
	run: ({ args }) => runAttackSimulate(args.scenario, args.policy),
});

const attackList = defineCommand({
	meta: { name: "list", description: "List built-in attack scenarios" },
	run: () => runAttackList(),
});

const attack = defineCommand({
	meta: { name: "attack", description: "Attack simulation framework" },
	subCommands: { simulate: attackSimulate, list: attackList },
});

const policyTest = defineCommand({
	meta: { name: "policy-test", description: "Test a policy against attack scenarios" },
	args: {
		policyFile: {
			type: "positional",
			description: "Policy file path to test",
			required: true,
		},
		scenarios: {
			type: "string",
			description: "Path to scenarios directory (uses built-in scenarios if omitted)",
		},
	},
	run: ({ args }) => runPolicyTestCommand(args.policyFile, args.scenarios),
});

const verifyReceipt = defineCommand({
	meta: { name: "verify-receipt", description: "Verify a signed decision receipt" },
	args: {
		receipt: {
			type: "positional",
			description: "Path to receipt JSON file",
			required: true,
		},
		publicKey: {
			type: "string",
			description: "Ed25519 public key (hex) for signature verification",
		},
	},
	run: ({ args }) => runVerifyReceipt(args.receipt, args.publicKey),
});

const cpExportAudit = defineCommand({
	meta: { name: "export-audit", description: "Export audit log as JSONL" },
	args: {
		db: {
			type: "string",
			description: "Path to control plane audit database",
			default: "./control-plane-audit.db",
		},
		out: {
			type: "string",
			description: "Output file path (defaults to stdout)",
		},
	},
	run: ({ args }) => runExportAudit(args.db, args.out),
});

const controlPlane = defineCommand({
	meta: { name: "control-plane", description: "Control plane management" },
	subCommands: { "export-audit": cpExportAudit },
});

const complianceReport = defineCommand({
	meta: { name: "compliance-report", description: "Generate compliance/evidence report" },
	args: {
		json: { type: "boolean", description: "Output as JSON", default: false },
		markdown: { type: "boolean", description: "Output as Markdown", default: false },
	},
	run: ({ args }) => runComplianceReport({ json: args.json, markdown: args.markdown }),
});

const main = defineCommand({
	meta: { name: "arikernel", version: "0.1.7", description: "Security runtime for AI agents" },
	subCommands: {
		attack,
		benchmark: benchmarkCmd,
		"compliance-report": complianceReport,
		"control-plane": controlPlane,
		init,
		policy,
		"policy-test": policyTest,
		replay,
		"replay-trace": replayTrace,
		run,
		simulate,
		trace,
		sidecar,
		"verify-receipt": verifyReceipt,
	},
});

runMain(main);
