import type {
	Capability,
	CapabilityClass,
	CapabilityConstraint,
	CapabilityGrant,
	CapabilityRequest,
	IssuanceDecision,
	Principal,
	SigningKey,
	TaintLabel,
} from "@arikernel/core";
import {
	CAPABILITY_CLASS_MAP,
	createCapabilityToken,
	generateId,
	generateNonce,
	now,
} from "@arikernel/core";
import { type PolicyEngine, matchesRule } from "@arikernel/policy-engine";
import type { TaintTracker } from "@arikernel/taint-tracker";
import type { TokenStore } from "./token-store.js";

const DEFAULT_LEASE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const DEFAULT_MAX_CALLS = 10;

/**
 * Taint sources considered untrusted for capability issuance.
 * Configurable via setUntrustedSources() to accommodate new sources
 * without requiring code changes.
 */
let UNTRUSTED_SOURCES: readonly string[] = ["web", "rag", "email", "retrieved-doc", "user-input"];

/** Override the default untrusted taint sources list. */
export function setUntrustedSources(sources: string[]): void {
	UNTRUSTED_SOURCES = Object.freeze([...sources]);
}

/** Get the current untrusted sources list. */
export function getUntrustedSources(): readonly string[] {
	return UNTRUSTED_SOURCES;
}

/**
 * Intersect two optional string arrays using capability narrowing semantics.
 *
 * Security invariant: the result must NEVER be broader than the base (b).
 * - Both undefined → undefined (no constraint from either side)
 * - Request undefined, base defined → base applies (request cannot broaden)
 * - Request defined, base undefined → request applies (narrowing is fine)
 * - Both defined → set intersection, with '*' acting as a wildcard that
 *   permits all values from the opposing set.
 */
function intersectStringLists(
	a: string[] | undefined,
	b: string[] | undefined,
): string[] | undefined {
	if (a === undefined && b === undefined) return undefined;
	// Request didn't specify → base constraint applies (cannot bypass by omitting)
	if (a === undefined) return b;
	// Base didn't specify → request constraint applies (narrowing)
	if (b === undefined) return a;
	// If base grants wildcard, request values are the constraint
	if (b.includes("*")) return a.filter((v) => v !== "*");
	// If request is wildcard, base values are the constraint
	if (a.includes("*")) return b;
	// Intersection: only values present in both
	const bSet = new Set(b);
	return a.filter((v) => bSet.has(v));
}

export class CapabilityIssuer {
	constructor(
		private readonly policyEngine: PolicyEngine,
		private readonly taintTracker: TaintTracker,
		private readonly tokenStore: TokenStore,
		private readonly signingKey?: SigningKey,
	) {}

	evaluate(request: CapabilityRequest, principal: Principal): IssuanceDecision {
		const timestamp = now();
		const mapping = CAPABILITY_CLASS_MAP[request.capabilityClass];

		// Step 1: does the principal have base capability for this tool class?
		const baseCap = principal.capabilities.find((c) => c.toolClass === mapping.toolClass);

		if (!baseCap) {
			return this.deny(
				request,
				timestamp,
				`Principal '${principal.name}' has no capability for ${mapping.toolClass}`,
			);
		}

		// Step 2: check if any requested actions are outside the base capability
		if (baseCap.actions && baseCap.actions.length > 0) {
			const allowed = mapping.actions.some((a) => baseCap.actions?.includes(a));
			if (!allowed) {
				return this.deny(
					request,
					timestamp,
					`Actions [${mapping.actions.join(", ")}] not permitted. Allowed: [${baseCap.actions.join(", ")}]`,
				);
			}
		}

		// Step 3: taint-based denial — untrusted provenance blocks sensitive capabilities
		const hasTaintRisk = this.assessTaintRisk(request.taintLabels, request.capabilityClass);

		if (hasTaintRisk) {
			const sources = request.taintLabels
				.filter((t) => UNTRUSTED_SOURCES.includes(t.source))
				.map((t) => `${t.source}:${t.origin}`)
				.join(", ");

			return this.deny(
				request,
				timestamp,
				`Capability '${request.capabilityClass}' denied: untrusted taint [${sources}] in provenance chain`,
			);
		}

		// Step 4: evaluate policy rules directly (skip constraint check — constraints apply at execution time)
		const syntheticToolCall = {
			id: generateId(),
			runId: "",
			sequence: 0,
			timestamp,
			principalId: request.principalId,
			toolClass: mapping.toolClass,
			action: mapping.actions[0],
			parameters: request.constraints?.parameters ?? {},
			taintLabels: request.taintLabels,
		};

		let matchedRule = undefined;
		for (const rule of this.policyEngine.getRules()) {
			if (matchesRule(rule.match, syntheticToolCall, request.taintLabels)) {
				if (rule.decision === "deny") {
					return this.deny(request, timestamp, rule.reason, rule);
				}
				matchedRule = rule;
				break;
			}
		}

		// Step 5: issue the grant
		const grant = this.issueGrant(request, baseCap, timestamp);

		// Sign the grant if a signing key is configured
		if (this.signingKey) {
			const signed = createCapabilityToken(grant, this.signingKey);
			this.tokenStore.store(grant, signed.signature, signed.algorithm);
		} else {
			this.tokenStore.store(grant);
		}

		return {
			requestId: request.id,
			granted: true,
			grant,
			reason: `Capability '${request.capabilityClass}' granted to '${principal.name}'`,
			matchedRule,
			taintLabels: request.taintLabels,
			timestamp,
		};
	}

	private assessTaintRisk(taintLabels: TaintLabel[], capabilityClass: CapabilityClass): boolean {
		const hasUntrustedTaint = taintLabels.some((t) => UNTRUSTED_SOURCES.includes(t.source));

		if (!hasUntrustedTaint) return false;

		// Sensitive capabilities that must not be issued with untrusted taint
		const sensitiveClasses: CapabilityClass[] = [
			"shell.exec",
			"database.read",
			"database.write",
			"file.write",
			"http.write",
		];

		return sensitiveClasses.includes(capabilityClass);
	}

	private issueGrant(
		request: CapabilityRequest,
		baseCap: Capability,
		timestamp: string,
	): CapabilityGrant {
		const issuedAt = timestamp;
		const expiresAt = new Date(new Date(issuedAt).getTime() + DEFAULT_LEASE_TTL_MS).toISOString();

		// Merge constraints: request constraints narrowed by base capability constraints
		const constraints = this.mergeConstraints(request.constraints ?? {}, baseCap.constraints ?? {});

		return {
			id: generateId(),
			requestId: request.id,
			principalId: request.principalId,
			capabilityClass: request.capabilityClass,
			constraints,
			lease: {
				issuedAt,
				expiresAt,
				maxCalls: DEFAULT_MAX_CALLS,
				callsUsed: 0,
			},
			taintContext: request.taintLabels,
			revoked: false,
			nonce: generateNonce(),
		};
	}

	/**
	 * Merge constraints using intersection semantics.
	 *
	 * When both requested and base define the same constraint field,
	 * the result is the intersection (only values present in both).
	 * This ensures grants can only narrow, never broaden, the base capability.
	 * A wildcard '*' in the base permits all values from the request.
	 */
	private mergeConstraints(
		requested: CapabilityConstraint,
		base: Capability["constraints"] & {},
	): CapabilityConstraint {
		return {
			allowedHosts: intersectStringLists(requested.allowedHosts, base.allowedHosts),
			allowedPaths: intersectStringLists(requested.allowedPaths, base.allowedPaths),
			allowedCommands: intersectStringLists(requested.allowedCommands, base.allowedCommands),
			allowedDatabases: intersectStringLists(requested.allowedDatabases, base.allowedDatabases),
			parameters: requested.parameters,
		};
	}

	private deny(
		request: CapabilityRequest,
		timestamp: string,
		reason: string,
		matchedRule?: import("@arikernel/core").PolicyRule,
	): IssuanceDecision {
		return {
			requestId: request.id,
			granted: false,
			reason,
			matchedRule,
			taintLabels: request.taintLabels,
			timestamp,
		};
	}
}
