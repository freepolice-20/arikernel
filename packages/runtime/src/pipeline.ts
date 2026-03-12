import type { AuditStore } from "@arikernel/audit-log";
import type {
	AuditEvent,
	Decision,
	Principal,
	SigningKey,
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
	verifyCapabilityToken,
} from "@arikernel/core";
import type { PolicyEngine } from "@arikernel/policy-engine";
import type { TaintTracker } from "@arikernel/taint-tracker";
import type { ExecutorRegistry } from "@arikernel/tool-executors";
import { applyBehavioralRule, evaluateBehavioralRules } from "./behavioral-rules.js";
import { validateCommand } from "./command-security.js";
import type { FirewallHooks } from "./hooks.js";
import { isPathAllowed } from "./path-security.js";
import type { PersistentTaintRegistry } from "./persistent-taint-registry.js";
import { type RunStateTracker, hasEncodedPayload, isSuspiciousGetExfil } from "./run-state.js";
import type { SecurityMode } from "./config.js";
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
		private readonly signingKey?: SigningKey,
		private readonly securityMode: SecurityMode = "dev",
		private readonly persistentTaint?: PersistentTaintRegistry,
	) {}

	async intercept(request: ToolCallRequest): Promise<ToolResult> {
		// Step 1: Validate
		toolCallRequestSchema.parse(request);

		// Step 1.1: Apply model-generated taint.
		// All tool call requests flowing through the pipeline originate from LLM output.
		// This taint label ensures behavioral rules can track model-originated content
		// through database writes, HTTP requests, and other tool executions.
		const inputLabels = request.taintLabels ?? [];
		const hasModelTaint = inputLabels.some((l) => l.source === "model-generated");
		const taintLabels: import("@arikernel/core").TaintLabel[] = hasModelTaint
			? inputLabels
			: [
					...inputLabels,
					{
						source: "model-generated" as const,
						origin: `${request.toolClass}.${request.action}`,
						confidence: 1.0,
						addedAt: now(),
					},
				];

		const toolCall: ToolCall = {
			id: generateId(),
			runId: this.runId,
			sequence: 0,
			timestamp: now(),
			principalId: this.principal.id,
			toolClass: request.toolClass,
			action: request.action,
			parameters: request.parameters,
			taintLabels,
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
			const url = String(toolCall.parameters.url ?? "");
			const isGetExfil =
				isSafeAction &&
				toolCall.toolClass === "http" &&
				isSuspiciousGetExfil(url);

			// Block GETs with query parameters after a budget is exhausted.
			// After sensitive read, budget is 0 — all parameterized GETs are blocked.
			let isGetBudgetExhausted = false;
			let isEncodedExfil = false;
			if (
				isSafeAction &&
				!isGetExfil &&
				toolCall.toolClass === "http" &&
				(toolCall.action === "get" || toolCall.action === "head")
			) {
				if (url.includes("?")) {
					isGetBudgetExhausted = this.runState.recordQuarantineGet();
				}
				// Detect base64/hex encoded payloads in query params
				if (!isGetBudgetExhausted && hasEncodedPayload(url)) {
					isEncodedExfil = true;
				}
			}

			if (!isSafeAction || isGetExfil || isGetBudgetExhausted || isEncodedExfil) {
				const reason = isEncodedExfil
					? `HTTP GET with encoded payload blocked in quarantine. Base64/hex data detected in query parameters.`
					: isGetBudgetExhausted
						? `HTTP GET with query parameters blocked: quarantine GET budget exhausted (${this.runState.quarantineGetCount} requests). Potential slow-drip exfiltration.`
						: isGetExfil
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
				this.runState.accumulateTaintLabels(toolCall.taintLabels);
				for (const label of toolCall.taintLabels) {
					this.persistentTaint?.recordTaintObserved(label.source);
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
				const httpUrl = String(toolCall.parameters.url ?? "");
				const isGetExfil =
					!isWriteEgress &&
					(toolCall.action === "get" || toolCall.action === "head") &&
					isSuspiciousGetExfil(httpUrl);

				// Track cumulative GET egress bytes per hostname
				if (
					(toolCall.action === "get" || toolCall.action === "head") &&
					httpUrl.includes("?")
				) {
					this.runState.recordHttpGetEgress(httpUrl);
				}

				// After a sensitive read, treat any GET with query params as potential exfil.
				// This closes the slow-drip gap where small GETs evade isSuspiciousGetExfil thresholds.
				const isSensitiveGetExfil =
					!isWriteEgress &&
					!isGetExfil &&
					(toolCall.action === "get" || toolCall.action === "head") &&
					this.runState.sensitiveReadObserved &&
					httpUrl.includes("?");

				if (isWriteEgress || isGetExfil || isSensitiveGetExfil) {
					this.runState.recordEgressAttempt();
					this.persistentTaint?.recordEgress(httpUrl);
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
					this.persistentTaint?.recordSensitiveRead(path);
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
				if (this.checkBehavioralRules(toolCall)) {
					this.denyQuarantinedAction(toolCall, "behavioral rule triggered by shell command");
				}
			}
			if (toolCall.toolClass === "database") {
				if (this.checkBehavioralRules(toolCall)) {
					this.denyQuarantinedAction(toolCall, "behavioral rule triggered by database operation");
				}
			}
		}

		// Step 1.5c: Capability enforcement — protected tool calls REQUIRE a valid grant
		const enforceTokens = this.securityMode === "secure" || !!this.tokenStore;
		if (enforceTokens && this.tokenStore) {
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

		// Step 2: Collect taint — merge tool-call labels with kernel-maintained run-level taint.
		// This ensures taint propagates even when a tool or agent omits taintLabels.
		let inputTaints = this.taintTracker.collectInputTaints(toolCall);
		if (this.runState && this.runState.tainted) {
			const runLabels = this.runState.accumulatedTaintLabels as import("@arikernel/core").TaintLabel[];
			if (runLabels.length > 0) {
				inputTaints = this.taintTracker.merge(inputTaints, [...runLabels]);
			}
		}

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
			if (!this.hooks.onApprovalRequired) {
				console.warn(
					`[arikernel] Policy returned 'require-approval' for ${toolCall.toolClass}.${toolCall.action} ` +
					`but no onApprovalRequired handler is registered. Action will be denied by default. ` +
					`Register a handler via hooks.onApprovalRequired to enable interactive approval.`,
				);
			}
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

		// Step 5.5: Content-based taint detection — scan tool output for injection patterns.
		// This derives taint from actual malicious content rather than relying on agent annotation.
		const contentTaints = this.taintTracker.scanOutput(result.data, toolCall.id);

		// Step 6: Propagate taint — merge executor auto-taints, content-derived taints, and propagated input taints
		const autoTaints = result.taintLabels;
		const propagated = this.taintTracker.propagate(inputTaints, toolCall.id);
		result.taintLabels = this.taintTracker.merge(autoTaints, contentTaints, propagated);

		// Step 6.1: Enforce run-level taint — tools cannot silently clear taint.
		// If the run is tainted, accumulated labels MUST appear in the output.
		// Only an explicit policy rule with tag "allow-taint-clear" can bypass this.
		if (this.runState && this.runState.tainted) {
			const runLabels = this.runState.accumulatedTaintLabels as import("@arikernel/core").TaintLabel[];
			result.taintLabels = this.taintTracker.merge(result.taintLabels, [...runLabels]);
		}

		// Step 6.2: Accumulate result taint labels into run-level state
		if (this.runState && result.taintLabels.length > 0) {
			this.runState.accumulateTaintLabels(result.taintLabels);

			// Push taint_observed for output-derived taint so behavioral rules can track it.
			// This covers both executor auto-taints (e.g. web from HTTP) and content-scan taints.
			//
			// We emit taint_observed whenever the output contains taint sources that were NOT
			// already present in the input request's taintLabels. This ensures:
			// - New taint from content scanning is always visible to behavioral rules
			// - New taint from executor auto-tainting is always visible
			// - Already-tainted follow-on requests still emit events for NEW sources
			// - Duplicate events are avoided for sources already reported via input taint
			const inputSources = new Set(toolCall.taintLabels.map((t) => t.source));
			const newOutputSources = [...new Set(result.taintLabels.map((t) => t.source))].filter(
				(s) => !inputSources.has(s),
			);
			if (newOutputSources.length > 0) {
				this.runState.pushEvent({
					timestamp: toolCall.timestamp,
					type: "taint_observed",
					toolClass: toolCall.toolClass,
					action: toolCall.action,
					taintSources: newOutputSources,
				});
				this.checkBehavioralRules(toolCall);
			}
		}

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
		const grant = this.tokenStore?.get(grantId);

		if (!grant) {
			this.denyAndThrow(toolCall, `Capability token not found: ${grantId}`);
		}

		// Verify cryptographic signature if signing is enabled
		if (this.signingKey) {
			const stored = this.tokenStore?.getStoredToken(grantId);
			if (!stored?.signature || !stored?.algorithm) {
				this.denyAndThrow(
					toolCall,
					`Signing is enabled but token '${grantId}' has no signature`,
				);
			}
			const verification = verifyCapabilityToken(
				{ grant, signature: stored.signature, algorithm: stored.algorithm },
				this.signingKey,
			);
			if (!verification.valid) {
				this.denyAndThrow(toolCall, `Token signature verification failed: ${verification.reason}`);
			}
		}

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

		// Atomically validate + consume one use (prevents TOCTOU double-spend)
		const consumed = this.tokenStore?.consume(grantId);
		if (consumed && !consumed.valid) {
			this.denyAndThrow(toolCall, `Capability token invalid: ${consumed.reason}`);
		}
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
			const db = String(toolCall.parameters.database ?? "");
			// Require an exact match on the explicit `database` parameter only.
			// The previous query-string regex fallback was dropped: matching a database
			// name as a word inside raw SQL is bypassable (comments, string literals,
			// identifiers), so only the structured parameter is trustworthy.
			if (!constraints.allowedDatabases.includes(db)) {
				return `Database not in allowed list: ${constraints.allowedDatabases.join(", ")}`;
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
