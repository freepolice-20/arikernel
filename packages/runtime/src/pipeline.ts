import type { AuditStore } from "@arikernel/audit-log";
import type {
	AuditEvent,
	Decision,
	Principal,
	ToolCall,
	ToolCallRequest,
	ToolResult,
} from "@arikernel/core";
import {
	ApprovalRequiredError,
	CAPABILITY_CLASS_MAP,
	ToolCallDeniedError,
	generateId,
	now,
	toolCallRequestSchema,
} from "@arikernel/core";
import type { PolicyEngine } from "@arikernel/policy-engine";
import type { TaintTracker } from "@arikernel/taint-tracker";
import type { ExecutorRegistry } from "@arikernel/tool-executors";
import { applyBehavioralRule, evaluateBehavioralRules } from "./behavioral-rules.js";
import { validateCommand } from "./command-security.js";
import type { FirewallHooks } from "./hooks.js";
import { isPathAllowed } from "./path-security.js";
import { type RunStateTracker, isSuspiciousGetExfil } from "./run-state.js";
import type { TokenStore } from "./token-store.js";

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
			const isSafeAction = this.runState.isAllowedInRestrictedMode(
				toolCall.toolClass,
				toolCall.action,
			);

			// Even safe GET/HEAD is blocked if the URL carries suspicious exfil patterns
			const isGetExfil =
				isSafeAction &&
				toolCall.toolClass === "http" &&
				isSuspiciousGetExfil(String(toolCall.parameters.url ?? ""));

			if (!isSafeAction || isGetExfil) {
				const reason = isGetExfil
					? `Suspicious data exfiltration via GET query parameters blocked in restricted mode. '${toolCall.toolClass}.${toolCall.action}' denied.`
					: `Run entered restricted mode at ${this.runState.restrictedAt} after ${this.runState.counters.deniedActions} denied sensitive actions. ` +
						`Only read-only safe actions are allowed. '${toolCall.toolClass}.${toolCall.action}' is blocked.`;
				const decision: Decision = {
					verdict: "deny",
					matchedRule: null,
					reason,
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
			// Track taint from the tool call — mark run as persistently tainted
			if (toolCall.taintLabels.length > 0) {
				for (const label of toolCall.taintLabels) {
					this.runState.markTainted(label.source);
				}
				this.runState.pushEvent({
					timestamp: toolCall.timestamp,
					type: "taint_observed",
					toolClass: toolCall.toolClass,
					action: toolCall.action,
					taintSources: toolCall.taintLabels.map((t) => t.source),
				});
				if (this.checkBehavioralRules(toolCall)) {
					this.denyQuarantinedAction(toolCall, "behavioral rule triggered by tainted input");
				}
			}

			if (toolCall.toolClass === "http") {
				const isWriteEgress = this.runState.isEgressAction(toolCall.action);
				const isGetExfil =
					!isWriteEgress &&
					(toolCall.action === "get" || toolCall.action === "head") &&
					isSuspiciousGetExfil(String(toolCall.parameters.url ?? ""));

				if (isWriteEgress || isGetExfil) {
					this.runState.recordEgressAttempt();
					this.runState.pushEvent({
						timestamp: toolCall.timestamp,
						type: "egress_attempt",
						toolClass: toolCall.toolClass,
						action: toolCall.action,
						metadata: { url: toolCall.parameters.url, getExfil: isGetExfil || undefined },
					});
					if (this.checkBehavioralRules(toolCall)) {
						this.denyQuarantinedAction(
							toolCall,
							isGetExfil
								? "behavioral rule triggered by suspicious GET exfiltration"
								: "behavioral rule triggered by egress attempt",
						);
					}
				}
			}
			if (toolCall.toolClass === "file") {
				const path = String(toolCall.parameters.path ?? "");
				if (this.runState.isSensitivePath(path)) {
					this.runState.recordSensitiveFileAttempt();
					this.runState.pushEvent({
						timestamp: toolCall.timestamp,
						type: "sensitive_read_attempt",
						toolClass: toolCall.toolClass,
						action: toolCall.action,
						metadata: { path },
					});
					if (this.checkBehavioralRules(toolCall)) {
						this.denyQuarantinedAction(
							toolCall,
							"behavioral rule triggered by sensitive file access",
						);
					}
				}
			}
			if (toolCall.toolClass === "shell") {
				const command = String(toolCall.parameters.command ?? "");
				this.runState.pushEvent({
					timestamp: toolCall.timestamp,
					type: "tool_call_allowed",
					toolClass: "shell",
					action: toolCall.action,
					metadata: { commandLength: command.length },
				});
				if (this.checkBehavioralRules(toolCall)) {
					this.denyQuarantinedAction(toolCall, "behavioral rule triggered by shell command");
				}
			}
			if (toolCall.toolClass === "database") {
				const query = String(toolCall.parameters.query ?? "");
				this.runState.pushEvent({
					timestamp: toolCall.timestamp,
					type: "tool_call_allowed",
					toolClass: "database",
					action: toolCall.action,
					metadata: { query: query.slice(0, 200) },
				});
				if (this.checkBehavioralRules(toolCall)) {
					this.denyQuarantinedAction(toolCall, "behavioral rule triggered by database operation");
				}
			}
		}

		// Step 1.5c: Capability enforcement — protected tool calls REQUIRE a valid grant
		if (this.tokenStore) {
			if (request.grantId) {
				this.validateToken(toolCall, request.grantId);
			} else if (isProtected(toolCall.toolClass, toolCall.action)) {
				const decision: Decision = {
					verdict: "deny",
					matchedRule: null,
					reason: `Capability token required for protected action '${toolCall.toolClass}.${toolCall.action}'. Request a capability grant before executing this tool call.`,
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
		const decision = this.policyEngine.evaluate(toolCall, inputTaints, this.principal.capabilities);

		this.hooks.onDecision?.(toolCall, decision);

		// Step 4: Enforce decision
		if (decision.verdict === "deny") {
			this.runState?.recordDeniedAction();
			if (this.runState) {
				this.runState.pushEvent({
					timestamp: toolCall.timestamp,
					type: "tool_call_denied",
					toolClass: toolCall.toolClass,
					action: toolCall.action,
					verdict: "deny",
				});
				// Behavioral rules may trigger quarantine here, but the action is
				// already being denied by policy — no extra denial needed.
				this.checkBehavioralRules(toolCall);
			}
			this.logEvent(toolCall, decision);
			throw new ToolCallDeniedError(toolCall, decision);
		}

		if (decision.verdict === "require-approval") {
			const approved = await this.hooks.onApprovalRequired?.(toolCall, decision);
			if (!approved) {
				const deniedDecision: Decision = {
					...decision,
					verdict: "deny",
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
				verdict: "deny",
				matchedRule: null,
				reason: `No executor registered for tool class: ${toolCall.toolClass}`,
				taintLabels: inputTaints,
				timestamp: now(),
			};
			this.runState?.recordDeniedAction();
			this.logEvent(toolCall, noExecDecision);
			throw new ToolCallDeniedError(toolCall, noExecDecision);
		}

		let result = await executor.execute(toolCall);

		// Step 6: Propagate taint — merge executor auto-taints with propagated input taints
		const autoTaints = result.taintLabels;
		const propagated = this.taintTracker.propagate(inputTaints, toolCall.id);
		result.taintLabels = this.taintTracker.merge(autoTaints, propagated);

		this.hooks.onExecute?.(toolCall, result);

		// Step 6.3: Output filtering (DLP hook)
		if (this.hooks.onOutputFilter) {
			result = await this.hooks.onOutputFilter(toolCall, result);
		}

		// Step 6.5: Push tool_call_allowed event for behavioral tracking
		if (this.runState) {
			this.runState.pushEvent({
				timestamp: toolCall.timestamp,
				type: "tool_call_allowed",
				toolClass: toolCall.toolClass,
				action: toolCall.action,
				verdict: "allow",
			});
			// Post-execution quarantine check — result is already produced but
			// future actions will be blocked. We don't deny the current result
			// since it already executed, but quarantine is now active.
			this.checkBehavioralRules(toolCall);
		}

		// Step 7: Audit log
		this.logEvent(toolCall, decision, result);

		return result;
	}

	private validateToken(toolCall: ToolCall, grantId: string): void {
		const validation = this.tokenStore?.validate(grantId);

		if (!validation.valid) {
			this.denyAndThrow(toolCall, `Capability token invalid: ${validation.reason}`);
		}

		const grant = this.tokenStore?.get(grantId)!;

		if (grant.principalId !== toolCall.principalId) {
			this.denyAndThrow(
				toolCall,
				`Capability token principal '${grant.principalId}' does not match caller '${toolCall.principalId}'`,
			);
		}

		const mapping = CAPABILITY_CLASS_MAP[grant.capabilityClass];

		if (mapping.toolClass !== toolCall.toolClass) {
			this.denyAndThrow(
				toolCall,
				`Token for '${grant.capabilityClass}' cannot be used for tool class '${toolCall.toolClass}'`,
			);
		}

		if (!mapping.actions.includes(toolCall.action)) {
			this.denyAndThrow(
				toolCall,
				`Token for '${grant.capabilityClass}' does not permit action '${toolCall.action}'`,
			);
		}

		const constraintViolation = this.checkGrantConstraints(toolCall, grant.constraints);
		if (constraintViolation) {
			this.denyAndThrow(toolCall, `Grant constraint violation: ${constraintViolation}`);
		}

		// Consume one use from the lease
		this.tokenStore?.consume(grantId);
	}

	/**
	 * Deny the current action because a behavioral rule just triggered quarantine.
	 * This prevents first-hit exfiltration where the triggering action itself would
	 * otherwise proceed despite causing quarantine.
	 */
	private denyQuarantinedAction(toolCall: ToolCall, context: string): never {
		const decision: Decision = {
			verdict: "deny",
			matchedRule: null,
			reason: `Action '${toolCall.toolClass}.${toolCall.action}' denied: ${context}. Run has been quarantined.`,
			taintLabels: toolCall.taintLabels,
			timestamp: now(),
		};
		this.runState?.recordDeniedAction();
		this.logEvent(toolCall, decision);
		throw new ToolCallDeniedError(toolCall, decision);
	}

	private denyAndThrow(toolCall: ToolCall, reason: string): never {
		const decision: Decision = {
			verdict: "deny",
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
		constraints: import("@arikernel/core").CapabilityConstraint,
	): string | null {
		if (constraints.allowedHosts && toolCall.toolClass === "http") {
			const url = String(toolCall.parameters.url ?? "");
			try {
				const hostname = new URL(url).hostname;
				if (
					!constraints.allowedHosts.includes("*") &&
					!constraints.allowedHosts.includes(hostname)
				) {
					return `Host '${hostname}' not in allowed hosts: ${constraints.allowedHosts.join(", ")}`;
				}
			} catch {
				return `Invalid URL: ${url}`;
			}
		}

		if (constraints.allowedCommands && toolCall.toolClass === "shell") {
			const command = String(toolCall.parameters.command ?? "");
			const violation = validateCommand(command, constraints.allowedCommands);
			if (violation) {
				return violation;
			}
		}

		if (constraints.allowedPaths && toolCall.toolClass === "file") {
			const path = String(toolCall.parameters.path ?? "");
			const { allowed, canonicalPath } = isPathAllowed(path, constraints.allowedPaths);
			if (!allowed) {
				return `Path '${canonicalPath}' not in allowed paths: ${constraints.allowedPaths.join(", ")}`;
			}
		}

		if (constraints.allowedDatabases && toolCall.toolClass === "database") {
			const query = String(toolCall.parameters.query ?? "");
			const dbMatch = constraints.allowedDatabases.some((db) => query.includes(db));
			if (!dbMatch) {
				return `Query does not reference any allowed database: ${constraints.allowedDatabases.join(", ")}`;
			}
		}

		return null;
	}

	/**
	 * Evaluate behavioral rules and apply quarantine if matched.
	 * Returns true if quarantine was newly triggered — callers should
	 * deny the current action to prevent first-hit exfiltration.
	 */
	private checkBehavioralRules(toolCall: ToolCall): boolean {
		if (!this.runState?.behavioralRulesEnabled) return false;
		const match = evaluateBehavioralRules(this.runState);
		if (!match) return false;
		const quarantine = applyBehavioralRule(this.runState, match);
		if (quarantine) {
			this.auditStore.appendSystemEvent(
				toolCall.runId,
				toolCall.principalId,
				"quarantine",
				quarantine.reason,
				{
					triggerType: quarantine.triggerType,
					ruleId: quarantine.ruleId,
					counters: quarantine.countersSnapshot,
					matchedEvents: quarantine.matchedEvents,
				},
			);
			return true;
		}
		return false;
	}

	private logEvent(toolCall: ToolCall, decision: Decision, result?: ToolResult): AuditEvent {
		const event = this.auditStore.append(toolCall, decision, result);
		this.hooks.onAudit?.(event);
		return event;
	}
}
