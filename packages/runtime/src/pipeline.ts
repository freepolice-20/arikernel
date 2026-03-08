import type {
	AuditEvent,
	Decision,
	Principal,
	ToolCall,
	ToolCallRequest,
	ToolResult,
} from '@arikernel/core';
import {
	ApprovalRequiredError,
	CAPABILITY_CLASS_MAP,
	ToolCallDeniedError,
	generateId,
	now,
	toolCallRequestSchema,
} from '@arikernel/core';
import type { AuditStore } from '@arikernel/audit-log';
import { PolicyEngine } from '@arikernel/policy-engine';
import { TaintTracker } from '@arikernel/taint-tracker';
import { ExecutorRegistry } from '@arikernel/tool-executors';
import type { FirewallHooks } from './hooks.js';
import { evaluateBehavioralRules, applyBehavioralRule } from './behavioral-rules.js';
import type { RunStateTracker } from './run-state.js';
import type { TokenStore } from './token-store.js';

/**
 * Precompute a lookup: toolClass -> Set of actions that are covered by
 * at least one CapabilityClass. Any tool call matching this map is
 * "protected" and MUST present a valid grant token.
 */
const PROTECTED_ACTIONS = new Map<string, Set<string>>();
for (const mapping of Object.values(CAPABILITY_CLASS_MAP)) {
	let actions = PROTECTED_ACTIONS.get(mapping.toolClass);
	if (!actions) {
		actions = new Set();
		PROTECTED_ACTIONS.set(mapping.toolClass, actions);
	}
	for (const action of mapping.actions) {
		actions.add(action);
	}
}

function isProtected(toolClass: string, action: string): boolean {
	return PROTECTED_ACTIONS.get(toolClass)?.has(action) ?? false;
}

export class Pipeline {
	constructor(
		private readonly runId: string,
		private readonly principal: Principal,
		private readonly policyEngine: PolicyEngine,
		private readonly taintTracker: TaintTracker,
		private readonly auditStore: AuditStore,
		private readonly executorRegistry: ExecutorRegistry,
		private readonly hooks: FirewallHooks,
		private readonly tokenStore?: TokenStore,
		private readonly runState?: RunStateTracker,
	) {}

	async intercept(request: ToolCallRequest): Promise<ToolResult> {
		// Step 1: Validate
		toolCallRequestSchema.parse(request);

		const toolCall: ToolCall = {
			id: generateId(),
			runId: this.runId,
			sequence: 0,
			timestamp: now(),
			principalId: this.principal.id,
			toolClass: request.toolClass,
			action: request.action,
			parameters: request.parameters,
			taintLabels: request.taintLabels ?? [],
			parentCallId: request.parentCallId,
			grantId: request.grantId,
		};

		// Step 1.5a: Run-state restriction — if the run is quarantined, only safe read-only actions pass
		if (this.runState?.restricted) {
			if (!this.runState.isAllowedInRestrictedMode(toolCall.toolClass, toolCall.action)) {
				const decision: Decision = {
					verdict: 'deny',
					matchedRule: null,
					reason: `Run entered restricted mode at ${this.runState.restrictedAt} after ${this.runState.counters.deniedActions} denied sensitive actions. ` +
						`Only read-only safe actions are allowed. '${toolCall.toolClass}.${toolCall.action}' is blocked.`,
					taintLabels: toolCall.taintLabels,
					timestamp: now(),
				};
				this.runState.recordDeniedAction();
				this.logEvent(toolCall, decision);
				throw new ToolCallDeniedError(toolCall, decision);
			}
		}

		// Step 1.5b: Track run-state signals and push security events
		if (this.runState) {
			// Track taint from the tool call
			if (toolCall.taintLabels.length > 0) {
				this.runState.pushEvent({
					timestamp: toolCall.timestamp,
					type: 'taint_observed',
					toolClass: toolCall.toolClass,
					action: toolCall.action,
					taintSources: toolCall.taintLabels.map((t) => t.source),
				});
				this.checkBehavioralRules(toolCall);
			}

			if (toolCall.toolClass === 'http' && this.runState.isEgressAction(toolCall.action)) {
				this.runState.recordEgressAttempt();
				this.runState.pushEvent({
					timestamp: toolCall.timestamp,
					type: 'egress_attempt',
					toolClass: toolCall.toolClass,
					action: toolCall.action,
					metadata: { url: toolCall.parameters.url },
				});
				this.checkBehavioralRules(toolCall);
			}
			if (toolCall.toolClass === 'file') {
				const path = String(toolCall.parameters.path ?? '');
				if (this.runState.isSensitivePath(path)) {
					this.runState.recordSensitiveFileAttempt();
					this.runState.pushEvent({
						timestamp: toolCall.timestamp,
						type: 'sensitive_read_attempt',
						toolClass: toolCall.toolClass,
						action: toolCall.action,
						metadata: { path },
					});
					this.checkBehavioralRules(toolCall);
				}
			}
		}

		// Step 1.5c: Capability enforcement — protected tool calls REQUIRE a valid grant
		if (this.tokenStore) {
			if (request.grantId) {
				this.validateToken(toolCall, request.grantId);
			} else if (isProtected(toolCall.toolClass, toolCall.action)) {
				const decision: Decision = {
					verdict: 'deny',
					matchedRule: null,
					reason: `Capability token required for protected action '${toolCall.toolClass}.${toolCall.action}'. ` +
						'Request a capability grant before executing this tool call.',
					taintLabels: toolCall.taintLabels,
					timestamp: now(),
				};
				this.runState?.recordDeniedAction();
				this.logEvent(toolCall, decision);
				throw new ToolCallDeniedError(toolCall, decision);
			}
		}

		// Step 2: Collect taint
		const inputTaints = this.taintTracker.collectInputTaints(toolCall);

		// Step 3: Evaluate policy
		const decision = this.policyEngine.evaluate(
			toolCall,
			inputTaints,
			this.principal.capabilities,
		);

		this.hooks.onDecision?.(toolCall, decision);

		// Step 4: Enforce decision
		if (decision.verdict === 'deny') {
			this.runState?.recordDeniedAction();
			if (this.runState) {
				this.runState.pushEvent({
					timestamp: toolCall.timestamp,
					type: 'tool_call_denied',
					toolClass: toolCall.toolClass,
					action: toolCall.action,
					verdict: 'deny',
				});
				this.checkBehavioralRules(toolCall);
			}
			this.logEvent(toolCall, decision);
			throw new ToolCallDeniedError(toolCall, decision);
		}

		if (decision.verdict === 'require-approval') {
			const approved = await this.hooks.onApprovalRequired?.(toolCall, decision);
			if (!approved) {
				const deniedDecision: Decision = {
					...decision,
					verdict: 'deny',
					reason: `${decision.reason} (approval denied by user)`,
				};
				this.runState?.recordDeniedAction();
				this.logEvent(toolCall, deniedDecision);
				throw new ApprovalRequiredError(toolCall, deniedDecision);
			}
		}

		// Step 5: Execute
		const executor = this.executorRegistry.get(toolCall.toolClass);
		if (!executor) {
			const noExecDecision: Decision = {
				verdict: 'deny',
				matchedRule: null,
				reason: `No executor registered for tool class: ${toolCall.toolClass}`,
				taintLabels: inputTaints,
				timestamp: now(),
			};
			this.runState?.recordDeniedAction();
			this.logEvent(toolCall, noExecDecision);
			throw new ToolCallDeniedError(toolCall, noExecDecision);
		}

		const result = await executor.execute(toolCall);

		// Step 6: Propagate taint — merge executor auto-taints with propagated input taints
		const autoTaints = result.taintLabels;
		const propagated = this.taintTracker.propagate(inputTaints, toolCall.id);
		result.taintLabels = this.taintTracker.merge(autoTaints, propagated);

		this.hooks.onExecute?.(toolCall, result);

		// Step 6.5: Push tool_call_allowed event for behavioral tracking
		if (this.runState) {
			this.runState.pushEvent({
				timestamp: toolCall.timestamp,
				type: 'tool_call_allowed',
				toolClass: toolCall.toolClass,
				action: toolCall.action,
				verdict: 'allow',
			});
			this.checkBehavioralRules(toolCall);
		}

		// Step 7: Audit log
		this.logEvent(toolCall, decision, result);

		return result;
	}

	private validateToken(toolCall: ToolCall, grantId: string): void {
		const validation = this.tokenStore!.validate(grantId);

		if (!validation.valid) {
			this.denyAndThrow(toolCall, `Capability token invalid: ${validation.reason}`);
		}

		const grant = this.tokenStore!.get(grantId)!;

		if (grant.principalId !== toolCall.principalId) {
			this.denyAndThrow(toolCall,
				`Capability token principal '${grant.principalId}' does not match caller '${toolCall.principalId}'`);
		}

		const mapping = CAPABILITY_CLASS_MAP[grant.capabilityClass];

		if (mapping.toolClass !== toolCall.toolClass) {
			this.denyAndThrow(toolCall,
				`Token for '${grant.capabilityClass}' cannot be used for tool class '${toolCall.toolClass}'`);
		}

		if (!mapping.actions.includes(toolCall.action)) {
			this.denyAndThrow(toolCall,
				`Token for '${grant.capabilityClass}' does not permit action '${toolCall.action}'`);
		}

		const constraintViolation = this.checkGrantConstraints(toolCall, grant.constraints);
		if (constraintViolation) {
			this.denyAndThrow(toolCall, `Grant constraint violation: ${constraintViolation}`);
		}

		// Consume one use from the lease
		this.tokenStore!.consume(grantId);
	}

	private denyAndThrow(toolCall: ToolCall, reason: string): never {
		const decision: Decision = {
			verdict: 'deny',
			matchedRule: null,
			reason,
			taintLabels: toolCall.taintLabels,
			timestamp: now(),
		};
		this.runState?.recordDeniedAction();
		this.logEvent(toolCall, decision);
		throw new ToolCallDeniedError(toolCall, decision);
	}

	private checkGrantConstraints(
		toolCall: ToolCall,
		constraints: import('@arikernel/core').CapabilityConstraint,
	): string | null {
		if (constraints.allowedHosts && toolCall.toolClass === 'http') {
			const url = String(toolCall.parameters.url ?? '');
			try {
				const hostname = new URL(url).hostname;
				if (!constraints.allowedHosts.includes(hostname)) {
					return `Host '${hostname}' not in allowed hosts: ${constraints.allowedHosts.join(', ')}`;
				}
			} catch {
				return `Invalid URL: ${url}`;
			}
		}

		if (constraints.allowedCommands && toolCall.toolClass === 'shell') {
			const command = String(toolCall.parameters.command ?? '');
			const binary = command.split(/\s+/)[0];
			if (!constraints.allowedCommands.includes(binary)) {
				return `Command '${binary}' not in allowed commands: ${constraints.allowedCommands.join(', ')}`;
			}
		}

		if (constraints.allowedPaths && toolCall.toolClass === 'file') {
			const path = String(toolCall.parameters.path ?? '');
			const allowed = constraints.allowedPaths.some((pattern) => {
				if (pattern.endsWith('/**')) {
					return path.startsWith(pattern.slice(0, -3));
				}
				return path === pattern;
			});
			if (!allowed) {
				return `Path '${path}' not in allowed paths: ${constraints.allowedPaths.join(', ')}`;
			}
		}

		if (constraints.allowedDatabases && toolCall.toolClass === 'database') {
			const query = String(toolCall.parameters.query ?? '');
			const dbMatch = constraints.allowedDatabases.some((db) => query.includes(db));
			if (!dbMatch) {
				return `Query does not reference any allowed database: ${constraints.allowedDatabases.join(', ')}`;
			}
		}

		return null;
	}

	private checkBehavioralRules(toolCall: ToolCall): void {
		if (!this.runState?.behavioralRulesEnabled) return;
		const match = evaluateBehavioralRules(this.runState);
		if (!match) return;
		const quarantine = applyBehavioralRule(this.runState, match);
		if (quarantine) {
			this.auditStore.appendSystemEvent(
				toolCall.runId,
				toolCall.principalId,
				'quarantine',
				quarantine.reason,
				{
					triggerType: quarantine.triggerType,
					ruleId: quarantine.ruleId,
					counters: quarantine.countersSnapshot,
					matchedEvents: quarantine.matchedEvents,
				},
			);
		}
	}

	private logEvent(toolCall: ToolCall, decision: Decision, result?: ToolResult): AuditEvent {
		const event = this.auditStore.append(toolCall, decision, result);
		this.hooks.onAudit?.(event);
		return event;
	}
}
