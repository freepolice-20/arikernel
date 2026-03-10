#!/usr/bin/env node
import { defineCommand, runMain } from 'citty';
import { runInit } from './commands/init.js';
import { runPolicyValidate, runPolicyList, runPolicyShow } from './commands/policy.js';
import { runReplay } from './commands/replay.js';
import { runAgent } from './commands/run.js';
import { runSimulate } from './commands/simulate.js';
import { runTrace } from './commands/trace.js';
import { runSidecar } from './commands/sidecar.js';
import { runReplayTrace } from './commands/replay-trace.js';
import { DEFAULT_PORT, DEFAULT_HOST } from '@arikernel/sidecar';

const init = defineCommand({
	meta: { name: 'init', description: 'Initialize arikernel config' },
	run: () => runInit(),
});

const policyValidate = defineCommand({
	meta: { name: 'validate', description: 'Validate a policy file' },
	args: {
		file: { type: 'positional', description: 'Policy file path', required: true },
	},
	run: ({ args }) => runPolicyValidate(args.file),
});

const policyList = defineCommand({
	meta: { name: 'list', description: 'List available security presets' },
	run: () => runPolicyList(),
});

const policyShow = defineCommand({
	meta: { name: 'show', description: 'Show details of a security preset' },
	args: {
		name: { type: 'positional', description: 'Preset name (e.g. safe, strict, research)', required: true },
	},
	run: ({ args }) => runPolicyShow(args.name),
});

const policy = defineCommand({
	meta: { name: 'policy', description: 'Policy and preset management' },
	subCommands: { validate: policyValidate, list: policyList, show: policyShow },
});

const replay = defineCommand({
	meta: { name: 'replay', description: 'Replay a run from audit log' },
	args: {
		db: { type: 'string', description: 'Audit database path', default: './arikernel-audit.db' },
		latest: { type: 'boolean', description: 'Replay the most recent run', default: false },
		verbose: { type: 'boolean', description: 'Show params, rule, and hash for each event', default: false },
		step: { type: 'boolean', description: 'Step through events with delay', default: false },
		runId: { type: 'positional', description: 'Run ID to replay (omit with --latest)', required: false },
	},
	run: ({ args }) => runReplay(args.db, args.runId, {
		latest: args.latest,
		verbose: args.verbose,
		step: args.step,
	}),
});

const run = defineCommand({
	meta: { name: 'run', description: 'Start firewall in run mode' },
	args: {
		policy: { type: 'string', description: 'Policy file path', default: './arikernel.policy.yaml' },
		auditLog: { type: 'string', description: 'Audit log path', default: './arikernel-audit.db' },
	},
	run: ({ args }) => runAgent(args.policy, args.auditLog),
});

const simulate = defineCommand({
	meta: { name: 'simulate', description: 'Run attack simulations' },
	args: {
		policy: { type: 'string', description: 'Policy file path (uses built-in safe defaults if omitted)' },
		db: { type: 'string', description: 'Audit database path', default: './arikernel-audit.db' },
		attackType: {
			type: 'positional',
			description: 'Attack type: prompt-injection, data-exfiltration, tool-escalation',
			required: false,
		},
	},
	run: ({ args }) => runSimulate(args.policy, args.attackType, args.db),
});

const trace = defineCommand({
	meta: { name: 'trace', description: 'Display security execution trace' },
	args: {
		db: { type: 'string', description: 'Audit database path', default: './arikernel-audit.db' },
		latest: { type: 'boolean', description: 'Trace the most recent run', default: false },
		runId: { type: 'positional', description: 'Run ID to trace (omit with --latest)', required: false },
	},
	run: ({ args }) => runTrace(args.db, args.runId, { latest: args.latest }),
});

const sidecar = defineCommand({
	meta: { name: 'sidecar', description: 'Start AriKernel as a sidecar enforcement proxy' },
	args: {
		policy: { type: 'string', description: 'Policy file path', default: './arikernel.policy.yaml' },
		port: { type: 'string', description: 'TCP port to listen on (default: 8787)', default: String(DEFAULT_PORT) },
		host: { type: 'string', description: 'Host/IP to bind to (default: 127.0.0.1). Use 0.0.0.0 to expose on all interfaces.', default: DEFAULT_HOST },
		auditLog: { type: 'string', description: 'Audit log path', default: './sidecar-audit.db' },
		authToken: { type: 'string', description: 'Bearer token for authenticating requests' },
	},
	run: ({ args }) => runSidecar({
		policy: args.policy,
		port: Number(args.port),
		host: args.host,
		auditLog: args.auditLog,
		authToken: args.authToken,
	}),
});

const replayTrace = defineCommand({
	meta: { name: 'replay-trace', description: 'Replay a JSON trace file through the kernel' },
	args: {
		tracePath: { type: 'positional', description: 'Path to the trace JSON file', required: true },
		policy: { type: 'string', description: 'Policy file override for what-if analysis' },
		preset: { type: 'string', description: 'Preset override for what-if analysis' },
		json: { type: 'boolean', description: 'Output raw JSON summary', default: false },
		verbose: { type: 'boolean', description: 'Show event-by-event comparison', default: false },
		timeline: { type: 'boolean', description: 'Show attack timeline visualization', default: false },
	},
	run: ({ args }) => runReplayTrace(args.tracePath, {
		policy: args.policy,
		preset: args.preset,
		json: args.json,
		verbose: args.verbose,
		timeline: args.timeline,
	}),
});

const main = defineCommand({
	meta: { name: 'arikernel', version: '0.1.1', description: 'Security runtime for AI agents' },
	subCommands: { init, policy, replay, 'replay-trace': replayTrace, run, simulate, trace, sidecar },
});

runMain(main);
