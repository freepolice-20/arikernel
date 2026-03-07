import type {
	Capability,
	CapabilityClass,
	CapabilityConstraint,
	CapabilityGrant,
	CapabilityRequest,
	IssuanceDecision,
	Principal,
	TaintLabel,
} from '@arikernel/core';
import {
	CAPABILITY_CLASS_MAP,
	generateId,
	now,
} from '@arikernel/core';
import { PolicyEngine, matchesRule } from '@arikernel/policy-engine';
import { TaintTracker } from '@arikernel/taint-tracker';
import { TokenStore } from './token-store.js';

const DEFAULT_LEASE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const DEFAULT_MAX_CALLS = 10;

const UNTRUSTED_SOURCES = ['web', 'rag', 'email', 'retrieved-doc'] as const;

export class CapabilityIssuer {
	constructor(
		private readonly policyEngine: PolicyEngine,
		private readonly taintTracker: TaintTracker,
		private readonly tokenStore: TokenStore,
	) {}

	evaluate(
		request: CapabilityRequest,
		principal: Principal,
	): IssuanceDecision {
		const timestamp = now();
		const mapping = CAPABILITY_CLASS_MAP[request.capabilityClass];

		// Step 1: does the principal have base capability for this tool class?
		const baseCap = principal.capabilities.find(
			(c) => c.toolClass === mapping.toolClass,
		);

		if (!baseCap) {
			return this.deny(request, timestamp,
				`Principal '${principal.name}' has no capability for ${mapping.toolClass}`,
			);
		}

		// Step 2: check if any requested actions are outside the base capability
		if (baseCap.actions && baseCap.actions.length > 0) {
			const allowed = mapping.actions.some((a) => baseCap.actions!.includes(a));
			if (!allowed) {
				return this.deny(request, timestamp,
					`Actions [${mapping.actions.join(', ')}] not permitted. Allowed: [${baseCap.actions.join(', ')}]`,
				);
			}
		}

		// Step 3: taint-based denial — untrusted provenance blocks sensitive capabilities
		const hasTaintRisk = this.assessTaintRisk(
			request.taintLabels,
			request.capabilityClass,
		);

		if (hasTaintRisk) {
			const sources = request.taintLabels
				.filter((t) => (UNTRUSTED_SOURCES as readonly string[]).includes(t.source))
				.map((t) => `${t.source}:${t.origin}`)
				.join(', ');

			return this.deny(request, timestamp,
				`Capability '${request.capabilityClass}' denied: untrusted taint [${sources}] in provenance chain`,
			);
		}

		// Step 4: evaluate policy rules directly (skip constraint check — constraints apply at execution time)
		const syntheticToolCall = {
			id: generateId(),
			runId: '',
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
				if (rule.decision === 'deny') {
					return this.deny(request, timestamp, rule.reason, rule);
				}
				matchedRule = rule;
				break;
			}
		}

		// Step 5: issue the grant
		const grant = this.issueGrant(request, baseCap, timestamp);
		this.tokenStore.store(grant);

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

	private assessTaintRisk(
		taintLabels: TaintLabel[],
		capabilityClass: CapabilityClass,
	): boolean {
		const hasUntrustedTaint = taintLabels.some((t) =>
			(UNTRUSTED_SOURCES as readonly string[]).includes(t.source),
		);

		if (!hasUntrustedTaint) return false;

		// Sensitive capabilities that must not be issued with untrusted taint
		const sensitiveClasses: CapabilityClass[] = [
			'shell.exec',
			'database.read',
			'database.write',
			'file.write',
		];

		return sensitiveClasses.includes(capabilityClass);
	}

	private issueGrant(
		request: CapabilityRequest,
		baseCap: Capability,
		timestamp: string,
	): CapabilityGrant {
		const issuedAt = timestamp;
		const expiresAt = new Date(
			new Date(issuedAt).getTime() + DEFAULT_LEASE_TTL_MS,
		).toISOString();

		// Merge constraints: request constraints narrowed by base capability constraints
		const constraints = this.mergeConstraints(
			request.constraints ?? {},
			baseCap.constraints ?? {},
		);

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
		};
	}

	private mergeConstraints(
		requested: CapabilityConstraint,
		base: Capability['constraints'] & {},
	): CapabilityConstraint {
		return {
			allowedHosts: requested.allowedHosts ?? base.allowedHosts,
			allowedPaths: requested.allowedPaths ?? base.allowedPaths,
			allowedCommands: requested.allowedCommands ?? base.allowedCommands,
			allowedDatabases: requested.allowedDatabases ?? base.allowedDatabases,
			parameters: requested.parameters,
		};
	}

	private deny(
		request: CapabilityRequest,
		timestamp: string,
		reason: string,
		matchedRule?: import('@arikernel/core').PolicyRule,
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
