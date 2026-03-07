#!/usr/bin/env node
import { defineCommand, runMain } from 'citty';
import { runInit } from './commands/init.js';
import { runPolicyValidate } from './commands/policy.js';
import { runReplay } from './commands/replay.js';
import { runAgent } from './commands/run.js';
import { runSimulate } from './commands/simulate.js';

const init = defineCommand({
	meta: { name: 'init', description: 'Initialize agent firewall config' },
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
		db: { type: 'string', description: 'Audit database path', default: './audit.db' },
		runId: { type: 'positional', description: 'Run ID to replay', required: true },
	},
	run: ({ args }) => runReplay(args.db, args.runId),
});

const run = defineCommand({
	meta: { name: 'run', description: 'Start firewall in run mode' },
	args: {
		policy: { type: 'string', description: 'Policy file path', default: './agent-firewall.policy.yaml' },
		auditLog: { type: 'string', description: 'Audit log path', default: './audit.db' },
	},
	run: ({ args }) => runAgent(args.policy, args.auditLog),
});

const simulate = defineCommand({
	meta: { name: 'simulate', description: 'Run attack simulations' },
	args: {
		policy: { type: 'string', description: 'Policy file path', default: './agent-firewall.policy.yaml' },
	},
	run: ({ args }) => runSimulate(args.policy),
});

const main = defineCommand({
	meta: { name: 'agent-firewall', version: '0.1.0', description: 'Security runtime for AI agents' },
	subCommands: { init, policy, replay, run, simulate },
});

runMain(main);
