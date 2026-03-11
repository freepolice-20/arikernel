import { AuditStore, type ReplayResult, replayRun } from "@arikernel/audit-log";
import type {
	AuditEvent,
	Capability,
	CapabilityClass,
	CapabilityConstraint,
	CapabilityGrant,
	CapabilityRequest,
	DelegatedCapability,
	DelegationResult,
	IssuanceDecision,
	Principal,
	TaintLabel,
	ToolCallRequest,
	ToolResult,
} from "@arikernel/core";
import {
	CAPABILITY_CLASS_MAP,
	createDelegatedPrincipal,
	delegateCapability,
	generateId,
	now,
	revokeDelegationsFrom,
} from "@arikernel/core";
import { PolicyEngine } from "@arikernel/policy-engine";
import { TaintTracker } from "@arikernel/taint-tracker";
import type { ToolExecutor } from "@arikernel/tool-executors";
import { ExecutorRegistry } from "@arikernel/tool-executors";
import { applyBehavioralRule, evaluateBehavioralRules } from "./behavioral-rules.js";
import type { EnforcementMode, FirewallOptions } from "./config.js";
import { validateOptions } from "./config.js";
import type { FirewallHooks } from "./hooks.js";
import { CapabilityIssuer } from "./issuer.js";
import { PersistentTaintRegistry } from "./persistent-taint-registry.js";
import { Pipeline } from "./pipeline.js";
import {
	type QuarantineInfo,
	type RunStateCounters,
	type RunStatePolicy,
	RunStateTracker,
} from "./run-state.js";
import { createSidecarProxies } from "./sidecar-proxy.js";
import { TokenStore } from "./token-store.js";

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
	private _persistentTaint: PersistentTaintRegistry | null = null;
	private readonly _mode: EnforcementMode;
	private readonly _sidecarOptions?: import("./config.js").SidecarConnectionOptions;
	readonly runId: string;

	constructor(options: FirewallOptions) {
		validateOptions(options);

		this._mode = options.mode ?? "embedded";
		this._sidecarOptions = options.sidecar;

		if (this._mode === "sidecar" && !options.sidecar) {
			throw new Error(
				'Firewall mode is "sidecar" but no sidecar connection options were provided. ' +
					"Set options.sidecar with baseUrl and authToken.",
			);
		}

		this.runId = generateId();

		this.principal = {
			id: generateId(),
			name: options.principal.name,
			capabilities: options.principal.capabilities,
		};

		this.policyEngine = new PolicyEngine(options.policies);
		this.taintTracker = new TaintTracker();
		this.auditStore = new AuditStore(options.auditLog ?? "./audit.db");
		this.executorRegistry = new ExecutorRegistry();
		this.tokenStore = new TokenStore();

		// In sidecar mode, replace all real executors with proxies that
		// delegate execution to the sidecar HTTP API. The host process
		// never executes tools directly.
		if (this._mode === "sidecar") {
			const proxyConfig = {
				baseUrl: options.sidecar!.baseUrl,
				principalId: options.sidecar!.principalId ?? options.principal.name,
				authToken: options.sidecar!.authToken,
			};
			for (const proxy of createSidecarProxies(proxyConfig)) {
				this.executorRegistry.register(proxy);
			}
		}
		this.issuer = new CapabilityIssuer(
			this.policyEngine,
			this.taintTracker,
			this.tokenStore,
			options.signingKey,
		);

		this._hooks = options.hooks ?? {};
		this._runState = new RunStateTracker(options.runStatePolicy);

		// Initialize persistent cross-run taint tracking
		if (options.persistentTaint?.enabled) {
			this._persistentTaint = new PersistentTaintRegistry(
				this.auditStore,
				this.principal.id,
				options.persistentTaint,
			);
			// Restore sticky flags from prior runs for this principal
			this._persistentTaint.initializeRunState(this._runState);
		}

		this.auditStore.startRun(this.runId, this.principal.id, {
			principal: options.principal,
			policies: Array.isArray(options.policies) ? "[inline]" : options.policies,
		});

		const securityMode = options.securityMode ?? (options.signingKey ? "secure" : "dev");

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
			options.signingKey,
			securityMode,
			this._persistentTaint ?? undefined,
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
		// Merge explicit taint labels with kernel-maintained run-level taint.
		// This ensures taint propagates to capability issuance even when the
		// agent omits taintLabels — the kernel tracks taint, not the agent.
		let taintLabels = options?.taintLabels ?? [];
		if (this._runState.tainted) {
			const runLabels = this._runState.accumulatedTaintLabels as TaintLabel[];
			if (runLabels.length > 0) {
				const seen = new Set(taintLabels.map((l) => `${l.source}:${l.origin}`));
				for (const label of runLabels) {
					const key = `${label.source}:${label.origin}`;
					if (!seen.has(key)) {
						seen.add(key);
						taintLabels = [...taintLabels, label];
					}
				}
			}
		}

		const request: CapabilityRequest = {
			id: generateId(),
			principalId: this.principal.id,
			capabilityClass,
			constraints: options?.constraints,
			taintLabels,
			justification: options?.justification,
			timestamp: now(),
		};

		// Deny unknown capability classes — fail closed instead of crashing
		if (!(capabilityClass in CAPABILITY_CLASS_MAP)) {
			this._runState.recordCapabilityRequest(false);
			const denied: IssuanceDecision = {
				requestId: request.id,
				granted: false,
				reason:
					`Unknown capability class '${capabilityClass}'. ` +
					`Valid classes: ${Object.keys(CAPABILITY_CLASS_MAP).join(", ")}`,
				taintLabels: request.taintLabels,
				timestamp: now(),
			};
			this._hooks.onIssuance?.(request, denied);
			return denied;
		}

		// Block non-read-only capability issuance in restricted mode
		if (this._runState.restricted) {
			const mapping = CAPABILITY_CLASS_MAP[capabilityClass];
			const safeReadOnly = mapping.actions.every((a) =>
				this._runState.isAllowedInRestrictedMode(mapping.toolClass, a),
			);
			if (!safeReadOnly) {
				this._runState.recordCapabilityRequest(false);
				this._runState.pushEvent({
					timestamp: request.timestamp,
					type: "capability_denied",
					toolClass: mapping.toolClass,
					metadata: { capabilityClass, reason: "restricted_mode" },
				});
				const denied: IssuanceDecision = {
					requestId: request.id,
					granted: false,
					reason:
						`Run is in restricted mode (entered at ${this._runState.restrictedAt}). ` +
						`Only read-only capabilities can be issued. '${capabilityClass}' is blocked.`,
					taintLabels: request.taintLabels,
					timestamp: now(),
				};
				this._hooks.onIssuance?.(request, denied);
				return denied;
			}
		}

		// Push capability_requested event before evaluation
		const mapping = CAPABILITY_CLASS_MAP[capabilityClass];
		this._runState.pushEvent({
			timestamp: request.timestamp,
			type: "capability_requested",
			toolClass: mapping.toolClass,
			metadata: { capabilityClass },
		});

		const decision = this.issuer.evaluate(request, this.principal);
		this._runState.recordCapabilityRequest(decision.granted);

		// Push granted/denied event
		this._runState.pushEvent({
			timestamp: decision.timestamp,
			type: decision.granted ? "capability_granted" : "capability_denied",
			toolClass: mapping.toolClass,
			metadata: { capabilityClass },
		});

		// Evaluate behavioral rules after capability events
		this.checkBehavioralRulesFromCapability(capabilityClass);

		this._hooks.onIssuance?.(request, decision);

		return decision;
	}

	registerExecutor(executor: ToolExecutor): void {
		if (this._mode === "sidecar") {
			throw new Error(
				"Cannot register local executors in sidecar mode. " +
					"Tool execution is delegated to the sidecar process. " +
					"Register executors on the sidecar server instead.",
			);
		}
		this.executorRegistry.register(executor);
	}

	async execute(request: ToolCallRequest): Promise<ToolResult> {
		return this.pipeline.intercept(request);
	}

	/**
	 * Observe real tool output after external execution (middleware mode).
	 *
	 * In middleware mode, stub executors don't perform real I/O — the framework
	 * executes the tool directly. This method allows adapters to feed real tool
	 * output back into the kernel for content scanning, taint derivation,
	 * run-state updates, and behavioral event emission.
	 *
	 * This closes the "middleware taint gap" for adapters that support it.
	 * Adapters that cannot provide output continue operating in degraded mode.
	 *
	 * @param observation - The tool output to observe
	 * @returns Taint labels derived from the output
	 */
	observeToolOutput(observation: {
		toolClass: string;
		action: string;
		data: unknown;
		callId?: string;
	}): TaintLabel[] {
		const callId = observation.callId ?? generateId();

		// Content scanning — detect injection patterns in real output
		const contentTaints = this.taintTracker.scanOutput(observation.data, callId);

		// Auto-taint — derive taint from tool class
		const autoTaints = this.deriveAutoTaint(observation.toolClass, observation.data);

		const allTaints = this.taintTracker.merge(contentTaints, autoTaints);
		if (allTaints.length === 0) return [];

		// Accumulate into run-state and emit events
		if (this._runState) {
			// Capture existing sources before accumulation for diff
			const priorSources = new Set(
				(this._runState.accumulatedTaintLabels as TaintLabel[]).map((t) => t.source),
			);

			this._runState.accumulateTaintLabels(allTaints);

			const newSources = [...new Set(allTaints.map((t) => t.source))].filter(
				(s) => !priorSources.has(s),
			);

			if (newSources.length > 0) {
				this._runState.pushEvent({
					timestamp: now(),
					type: "taint_observed",
					toolClass: observation.toolClass,
					action: observation.action,
					taintSources: newSources,
				});

				// Check behavioral rules after taint event
				if (this._runState.behavioralRulesEnabled) {
					const match = evaluateBehavioralRules(this._runState);
					if (match) {
						const quarantine = applyBehavioralRule(this._runState, match);
						if (quarantine) {
							this.auditStore.appendSystemEvent(
								this.runId,
								this.principal.id,
								"quarantine",
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
				}
			}
		}

		return allTaints;
	}

	private deriveAutoTaint(toolClass: string, data: unknown): TaintLabel[] {
		const ts = now();
		if (toolClass === "http") {
			let origin = "unknown";
			if (typeof data === "object" && data !== null && "url" in data) {
				try {
					origin = new URL(String((data as Record<string, unknown>).url)).hostname;
				} catch { /* keep unknown */ }
			}
			return [{ source: "web", origin, confidence: 1.0, addedAt: ts }];
		}
		if (toolClass === "retrieval") {
			return [{ source: "rag", origin: "retrieval", confidence: 0.9, addedAt: ts }];
		}
		return [];
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

	/** Quarantine metadata if the run has been quarantined. */
	get quarantineInfo(): QuarantineInfo | null {
		return this._runState.quarantineInfo;
	}

	/** Kernel-maintained taint state for this run. */
	get taintState(): import("@arikernel/core").TaintState {
		return this._runState.taintState;
	}

	/** Whether this run has observed a sensitive file read (sticky flag). */
	get sensitiveReadObserved(): boolean {
		return this._runState.sensitiveReadObserved;
	}

	/**
	 * Quarantine this firewall externally (e.g., from a cross-principal correlator alert).
	 * Returns QuarantineInfo if newly quarantined, null if already restricted.
	 */
	quarantineExternal(ruleId: string, reason: string): QuarantineInfo | null {
		const result = this._runState.quarantineByRule(ruleId, reason, []);
		if (result) {
			this.auditStore.appendSystemEvent(
				this.runId,
				this.principal.id,
				"quarantine",
				reason,
				{
					triggerType: "cross_principal_alert",
					ruleId,
					counters: result.countersSnapshot,
				},
			);
		}
		return result;
	}

	/**
	 * Inject external taint labels into this firewall's run-state.
	 * Used by cross-principal systems (e.g., SharedTaintRegistry) to propagate
	 * contamination from one principal's actions to another.
	 */
	injectExternalTaint(labels: TaintLabel[]): void {
		if (labels.length === 0) return;
		this._runState.accumulateTaintLabels(labels);
		for (const label of labels) {
			this._runState.pushEvent({
				timestamp: now(),
				type: "taint_observed",
				toolClass: "external",
				action: "inject",
				taintSources: [label.source],
			});
		}
	}

	private checkBehavioralRulesFromCapability(capabilityClass: string): void {
		if (!this._runState.behavioralRulesEnabled) return;
		const match = evaluateBehavioralRules(this._runState);
		if (!match) return;
		const quarantine = applyBehavioralRule(this._runState, match);
		if (quarantine) {
			this.auditStore.appendSystemEvent(
				this.runId,
				this.principal.id,
				"quarantine",
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

	/**
	 * Delegate a subset of this firewall's principal capabilities to a child principal.
	 *
	 * The child receives the intersection of the parent's capabilities and
	 * the requested capabilities — delegation can only narrow, never widen.
	 *
	 * Returns a new Firewall instance bound to the child principal.
	 */
	delegateToChild(
		childName: string,
		requestedCapabilities: Capability[],
	): { firewall: Firewall; denied: DelegationResult[] } {
		const childId = generateId();
		const { principal: childPrincipal, denied } = createDelegatedPrincipal(
			{ ...this.principal, capabilities: this.principal.capabilities as DelegatedCapability[] },
			childId,
			childName,
			requestedCapabilities,
			now(),
		);

		const childFirewall = new Firewall({
			principal: {
				name: childPrincipal.name,
				capabilities: childPrincipal.capabilities,
			},
			policies: [...this.policyEngine.getRules()],
			hooks: this._hooks,
			runStatePolicy: this._runState.policy,
			mode: this._mode,
			sidecar: this._sidecarOptions,
		});

		// Override the generated principal to preserve parentId and delegation metadata
		(childFirewall as any).principal = childPrincipal;

		return { firewall: childFirewall, denied };
	}

	/**
	 * Revoke all capabilities that were delegated through a specific principal.
	 *
	 * Transitive: if A → B → C, revoking B removes C's delegated capabilities too.
	 */
	revokeDelegationsFrom(principalId: string): void {
		this.principal.capabilities = revokeDelegationsFrom(
			this.principal.capabilities as DelegatedCapability[],
			principalId,
		);
	}

	/** The enforcement mode this firewall is operating in. */
	get enforcementMode(): EnforcementMode {
		return this._mode;
	}

	/** The principal bound to this firewall instance. */
	get principalInfo(): Readonly<Principal> {
		return this.principal;
	}

	/** The persistent taint registry, if cross-run tracking is enabled. */
	get persistentTaintRegistry(): PersistentTaintRegistry | null {
		return this._persistentTaint;
	}

	close(): void {
		// Purge expired persistent taint events on close
		this._persistentTaint?.purgeExpired();
		this.auditStore.endRun(this.runId);
		this.auditStore.close();
	}
}

export function createFirewall(options: FirewallOptions): Firewall {
	return new Firewall(options);
}
