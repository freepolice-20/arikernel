#!/usr/bin/env node
import { defineCommand, runMain } from 'citty';
import { runInit } from './commands/init.js';
import { runPolicyValidate } from './commands/policy.js';
import { runReplay } from './commands/replay.js';
import { runAgent } from './commands/run.js';
import { runSimulate } from './commands/simulate.js';
import { runTrace } from './commands/trace.js';

const init = defineCommand({
	meta: { name: 'init', description: 'Initialize arikernel config' },
	run: () => runInit(),
});

const policy = defineCommand({
	meta: { name: 'policy', description: 'Validate a policy file' },
	args: {
		file: { type: 'positional', description: 'Policy file path', required: true },
	},
	run: ({ args }) => runPolicyValidate(args.file),
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

const main = defineCommand({
	meta: { name: 'arikernel', version: '0.2.2', description: 'Security runtime for AI agents' },
	subCommands: { init, policy, replay, run, simulate, trace },
});

runMain(main);
