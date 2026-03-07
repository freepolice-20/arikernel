import type {
	AuditEvent,
	CapabilityGrant,
	Decision,
	Principal,
	ToolCall,
	ToolCallRequest,
	ToolResult,
} from '@agent-firewall/core';
import {
	ApprovalRequiredError,
	CAPABILITY_CLASS_MAP,
	ToolCallDeniedError,
	generateId,
	now,
	toolCallRequestSchema,
} from '@agent-firewall/core';
import type { AuditStore } from '@agent-firewall/audit-log';
import { PolicyEngine } from '@agent-firewall/policy-engine';
import { TaintTracker } from '@agent-firewall/taint-tracker';
import { ExecutorRegistry } from '@agent-firewall/tool-executors';
import type { FirewallHooks } from './hooks.js';
import type { TokenStore } from './token-store.js';

export class Pipeline {
	private sequence = 0;

	constructor(
		private readonly runId: string,
		private readonly principal: Principal,
		private readonly policyEngine: PolicyEngine,
		private readonly taintTracker: TaintTracker,
		private readonly auditStore: AuditStore,
		private readonly executorRegistry: ExecutorRegistry,
		private readonly hooks: FirewallHooks,
		private readonly tokenStore?: TokenStore,
	) {}

	async intercept(request: ToolCallRequest): Promise<ToolResult> {
		// Step 1: Validate
		toolCallRequestSchema.parse(request);

		const toolCall: ToolCall = {
			id: generateId(),
			runId: this.runId,
			sequence: this.sequence++,
			timestamp: now(),
			principalId: this.principal.id,
			toolClass: request.toolClass,
			action: request.action,
			parameters: request.parameters,
			taintLabels: request.taintLabels ?? [],
			parentCallId: request.parentCallId,
			grantId: request.grantId,
		};

		// Step 1.5: Validate capability token if provided
		if (request.grantId && this.tokenStore) {
			const tokenResult = this.validateToken(toolCall, request.grantId);
			if (tokenResult) return tokenResult;
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
			this.logEvent(toolCall, noExecDecision);
			throw new ToolCallDeniedError(toolCall, noExecDecision);
		}

		const result = await executor.execute(toolCall);

		// Step 6: Propagate taint
		result.taintLabels = this.taintTracker.propagate(inputTaints, toolCall.id);

		this.hooks.onExecute?.(toolCall, result);

		// Step 7: Audit log
		this.logEvent(toolCall, decision, result);

		return result;
	}

	private validateToken(toolCall: ToolCall, grantId: string): Promise<ToolResult> | null {
		const validation = this.tokenStore!.validate(grantId);

		if (!validation.valid) {
			const decision: Decision = {
				verdict: 'deny',
				matchedRule: null,
				reason: `Capability token invalid: ${validation.reason}`,
				taintLabels: toolCall.taintLabels,
				timestamp: now(),
			};
			this.logEvent(toolCall, decision);
			throw new ToolCallDeniedError(toolCall, decision);
		}

		const grant = this.tokenStore!.get(grantId)!;
		const mapping = CAPABILITY_CLASS_MAP[grant.capabilityClass];

		if (mapping.toolClass !== toolCall.toolClass) {
			const decision: Decision = {
				verdict: 'deny',
				matchedRule: null,
				reason: `Token for '${grant.capabilityClass}' cannot be used for tool class '${toolCall.toolClass}'`,
				taintLabels: toolCall.taintLabels,
				timestamp: now(),
			};
			this.logEvent(toolCall, decision);
			throw new ToolCallDeniedError(toolCall, decision);
		}

		if (!mapping.actions.includes(toolCall.action)) {
			const decision: Decision = {
				verdict: 'deny',
				matchedRule: null,
				reason: `Token for '${grant.capabilityClass}' does not permit action '${toolCall.action}'`,
				taintLabels: toolCall.taintLabels,
				timestamp: now(),
			};
			this.logEvent(toolCall, decision);
			throw new ToolCallDeniedError(toolCall, decision);
		}

		// Consume one use from the lease
		this.tokenStore!.consume(grantId);

		return null; // null = validation passed, proceed with normal flow
	}

	private logEvent(toolCall: ToolCall, decision: Decision, result?: ToolResult): AuditEvent {
		const event = this.auditStore.append(toolCall, decision, result);
		this.hooks.onAudit?.(event);
		return event;
	}
}
