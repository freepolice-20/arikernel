import type { AuditEvent, Principal, ToolCallRequest, ToolResult } from '@agent-firewall/core';
import { generateId } from '@agent-firewall/core';
import { AuditStore, replayRun, type ReplayResult } from '@agent-firewall/audit-log';
import { PolicyEngine } from '@agent-firewall/policy-engine';
import { TaintTracker } from '@agent-firewall/taint-tracker';
import { ExecutorRegistry } from '@agent-firewall/tool-executors';
import type { FirewallOptions } from './config.js';
import { validateOptions } from './config.js';
import { Pipeline } from './pipeline.js';

export class Firewall {
	private principal: Principal;
	private policyEngine: PolicyEngine;
	private taintTracker: TaintTracker;
	private auditStore: AuditStore;
	private executorRegistry: ExecutorRegistry;
	private pipeline: Pipeline;
	readonly runId: string;

	constructor(options: FirewallOptions) {
		validateOptions(options);

		this.runId = generateId();

		this.principal = {
			id: generateId(),
			name: options.principal.name,
			capabilities: options.principal.capabilities,
		};

		this.policyEngine = new PolicyEngine(options.policies);
		this.taintTracker = new TaintTracker();
		this.auditStore = new AuditStore(options.auditLog ?? './audit.db');
		this.executorRegistry = new ExecutorRegistry();

		this.auditStore.startRun(this.runId, this.principal.id, {
			principal: options.principal,
			policies: Array.isArray(options.policies) ? '[inline]' : options.policies,
		});

		this.pipeline = new Pipeline(
			this.runId,
			this.principal,
			this.policyEngine,
			this.taintTracker,
			this.auditStore,
			this.executorRegistry,
			options.hooks ?? {},
		);
	}

	async execute(request: ToolCallRequest): Promise<ToolResult> {
		return this.pipeline.intercept(request);
	}

	replay(runId?: string): ReplayResult | null {
		return replayRun(this.auditStore, runId ?? this.runId);
	}

	getEvents(runId?: string): AuditEvent[] {
		return this.auditStore.queryRun(runId ?? this.runId);
	}

	close(): void {
		this.auditStore.endRun(this.runId);
		this.auditStore.close();
	}
}

export function createFirewall(options: FirewallOptions): Firewall {
	return new Firewall(options);
}
