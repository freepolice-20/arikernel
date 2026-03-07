import type {
	AuditEvent,
	CapabilityClass,
	CapabilityConstraint,
	CapabilityGrant,
	CapabilityRequest,
	IssuanceDecision,
	Principal,
	TaintLabel,
	ToolCallRequest,
	ToolResult,
} from '@agent-firewall/core';
import { CAPABILITY_CLASS_MAP, generateId, now } from '@agent-firewall/core';
import { AuditStore, replayRun, type ReplayResult } from '@agent-firewall/audit-log';
import { PolicyEngine } from '@agent-firewall/policy-engine';
import { TaintTracker } from '@agent-firewall/taint-tracker';
import { ExecutorRegistry } from '@agent-firewall/tool-executors';
import type { FirewallOptions } from './config.js';
import { validateOptions } from './config.js';
import type { FirewallHooks } from './hooks.js';
import { CapabilityIssuer } from './issuer.js';
import { Pipeline } from './pipeline.js';
import { RunStateTracker, type RunStateCounters, type RunStatePolicy } from './run-state.js';
import { TokenStore } from './token-store.js';

export class Firewall {
	private principal: Principal;
	private policyEngine: PolicyEngine;
	private taintTracker: TaintTracker;
	private auditStore: AuditStore;
	private executorRegistry: ExecutorRegistry;
	private pipeline: Pipeline;
	private issuer: CapabilityIssuer;
	private tokenStore: TokenStore;
	private _hooks: FirewallHooks;
	private _runState: RunStateTracker;
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
		this.tokenStore = new TokenStore();
		this.issuer = new CapabilityIssuer(
			this.policyEngine,
			this.taintTracker,
			this.tokenStore,
		);

		this._hooks = options.hooks ?? {};
		this._runState = new RunStateTracker(options.runStatePolicy);

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
			this.tokenStore,
			this._runState,
		);
	}

	requestCapability(
		capabilityClass: CapabilityClass,
		options?: {
			constraints?: CapabilityConstraint;
			taintLabels?: TaintLabel[];
			justification?: string;
		},
	): IssuanceDecision {
		const request: CapabilityRequest = {
			id: generateId(),
			principalId: this.principal.id,
			capabilityClass,
			constraints: options?.constraints,
			taintLabels: options?.taintLabels ?? [],
			justification: options?.justification,
			timestamp: now(),
		};

		// Block non-read-only capability issuance in restricted mode
		if (this._runState.restricted) {
			const mapping = CAPABILITY_CLASS_MAP[capabilityClass];
			const safeReadOnly = mapping.actions.every(
				(a) => this._runState.isAllowedInRestrictedMode(mapping.toolClass, a),
			);
			if (!safeReadOnly) {
				this._runState.recordCapabilityRequest(false);
				const denied: IssuanceDecision = {
					requestId: request.id,
					granted: false,
					reason: `Run is in restricted mode (entered at ${this._runState.restrictedAt}). ` +
						`Only read-only capabilities can be issued. '${capabilityClass}' is blocked.`,
					taintLabels: request.taintLabels,
					timestamp: now(),
				};
				this._hooks.onIssuance?.(request, denied);
				return denied;
			}
		}

		const decision = this.issuer.evaluate(request, this.principal);
		this._runState.recordCapabilityRequest(decision.granted);

		this._hooks.onIssuance?.(request, decision);

		return decision;
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

	activeGrants(): CapabilityGrant[] {
		return this.tokenStore.activeGrants(this.principal.id);
	}

	revokeGrant(grantId: string): boolean {
		return this.tokenStore.revoke(grantId);
	}

	/** Whether this run has entered restricted mode. */
	get isRestricted(): boolean {
		return this._runState.restricted;
	}

	/** Timestamp when restricted mode was entered, or null. */
	get restrictedAt(): string | null {
		return this._runState.restrictedAt;
	}

	/** Current run-state counters. */
	get runStateCounters(): RunStateCounters {
		return { ...this._runState.counters };
	}

	close(): void {
		this.auditStore.endRun(this.runId);
		this.auditStore.close();
	}
}

export function createFirewall(options: FirewallOptions): Firewall {
	return new Firewall(options);
}
