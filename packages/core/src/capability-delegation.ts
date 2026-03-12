import type { Capability, CapabilityConstraints, Principal } from "./types/principal.js";

/**
 * Metadata tracking the delegation chain for a capability.
 */
export interface DelegationMetadata {
	/** Principal ID that issued the delegation. */
	issuedBy: string;
	/** Principal ID that received the delegation. */
	delegatedTo: string;
	/** Ordered chain of principal IDs from root to current holder. */
	delegationChain: string[];
	/** Timestamp when the delegation was created. */
	delegatedAt: string;
}

/**
 * A capability with delegation provenance attached.
 */
export interface DelegatedCapability extends Capability {
	delegation?: DelegationMetadata;
}

/**
 * Result of a delegation attempt.
 */
export interface DelegationResult {
	granted: boolean;
	capability?: DelegatedCapability;
	reason: string;
}

/**
 * Intersect two optional string arrays for capability narrowing.
 *
 * Invariant: result is never broader than `base`.
 * - Both undefined → undefined (unconstrained)
 * - Only base defined → base applies (child cannot bypass by omitting)
 * - Only request defined → request applies (narrowing)
 * - Both defined → set intersection
 */
function intersectStringLists(
	requested: string[] | undefined,
	base: string[] | undefined,
): string[] | undefined {
	if (requested === undefined && base === undefined) return undefined;
	if (requested === undefined) return base;
	if (base === undefined) return requested;
	const baseSet = new Set(base);
	return requested.filter((v) => baseSet.has(v));
}

/**
 * Intersect two CapabilityConstraints, producing the narrowest result.
 */
function intersectConstraints(
	requested: CapabilityConstraints | undefined,
	base: CapabilityConstraints | undefined,
): CapabilityConstraints | undefined {
	if (!requested && !base) return undefined;
	const r = requested ?? {};
	const b = base ?? {};

	const result: CapabilityConstraints = {
		allowedPaths: intersectStringLists(r.allowedPaths, b.allowedPaths),
		allowedHosts: intersectStringLists(r.allowedHosts, b.allowedHosts),
		allowedCommands: intersectStringLists(r.allowedCommands, b.allowedCommands),
		allowedDatabases: intersectStringLists(r.allowedDatabases, b.allowedDatabases),
		maxCallsPerMinute:
			r.maxCallsPerMinute !== undefined && b.maxCallsPerMinute !== undefined
				? Math.min(r.maxCallsPerMinute, b.maxCallsPerMinute)
				: (r.maxCallsPerMinute ?? b.maxCallsPerMinute),
	};

	// Strip undefined fields
	for (const key of Object.keys(result) as (keyof CapabilityConstraints)[]) {
		if (result[key] === undefined) delete result[key];
	}

	return Object.keys(result).length > 0 ? result : undefined;
}

/**
 * Intersect two action lists for capability narrowing.
 */
function intersectActions(
	requested: string[] | undefined,
	base: string[] | undefined,
): string[] | undefined {
	if (!requested && !base) return undefined;
	if (!requested) return base;
	if (!base) return requested;
	const baseSet = new Set(base);
	return requested.filter((a) => baseSet.has(a));
}

/**
 * Compute the effective delegated capability by intersecting a parent's
 * capability with the child's request.
 *
 * Core invariant: capabilities can only narrow, never widen.
 *
 *   effective = parent_capability ∩ child_request
 *
 * If the intersection is empty (no overlapping actions or the tool class
 * doesn't match), delegation is denied.
 */
export function delegateCapability(
	parentCapability: DelegatedCapability,
	requestedCapability: Capability,
	parentId: string,
	childId: string,
	timestamp?: string,
): DelegationResult {
	// Tool class must match
	if (parentCapability.toolClass !== requestedCapability.toolClass) {
		return {
			granted: false,
			reason:
				`Tool class mismatch: parent has '${parentCapability.toolClass}', ` +
				`child requested '${requestedCapability.toolClass}'`,
		};
	}

	// Intersect actions
	const actions = intersectActions(requestedCapability.actions, parentCapability.actions);
	if (actions && actions.length === 0) {
		return {
			granted: false,
			reason:
				`No overlapping actions: parent allows [${parentCapability.actions?.join(", ")}], ` +
				`child requested [${requestedCapability.actions?.join(", ")}]`,
		};
	}

	// Intersect constraints
	const constraints = intersectConstraints(
		requestedCapability.constraints,
		parentCapability.constraints,
	);

	// Build delegation chain
	const existingChain = parentCapability.delegation?.delegationChain ?? [parentId];
	const delegationChain = [...existingChain, childId];

	const delegated: DelegatedCapability = {
		toolClass: parentCapability.toolClass,
		actions,
		constraints,
		delegation: {
			issuedBy: parentId,
			delegatedTo: childId,
			delegationChain,
			delegatedAt: timestamp ?? new Date().toISOString(),
		},
	};

	return {
		granted: true,
		capability: delegated,
		reason: `Delegated '${parentCapability.toolClass}' from ${parentId} to ${childId}`,
	};
}

/**
 * Create a child principal with capabilities delegated from a parent.
 *
 * Each requested capability is intersected with the parent's matching
 * capability. Only capabilities the parent actually holds can be delegated.
 */
export function createDelegatedPrincipal(
	parent: Principal & { capabilities: DelegatedCapability[] },
	childId: string,
	childName: string,
	requestedCapabilities: Capability[],
	timestamp?: string,
): {
	principal: Principal & { parentId: string; capabilities: DelegatedCapability[] };
	denied: DelegationResult[];
} {
	const ts = timestamp ?? new Date().toISOString();
	const granted: DelegatedCapability[] = [];
	const denied: DelegationResult[] = [];

	for (const req of requestedCapabilities) {
		// Find the parent's matching capability for this tool class
		const parentCap = parent.capabilities.find((c) => c.toolClass === req.toolClass);
		if (!parentCap) {
			denied.push({
				granted: false,
				reason: `Parent '${parent.name}' has no capability for '${req.toolClass}'`,
			});
			continue;
		}

		const result = delegateCapability(parentCap, req, parent.id, childId, ts);
		if (result.granted && result.capability) {
			granted.push(result.capability);
		} else {
			denied.push(result);
		}
	}

	return {
		principal: {
			id: childId,
			name: childName,
			parentId: parent.id,
			capabilities: granted,
		},
		denied,
	};
}

/**
 * Validate that a delegation chain has not been tampered with.
 *
 * Checks that each hop in the chain narrows (or preserves) the capabilities
 * of the previous hop. Returns true if the chain is valid.
 */
export function validateDelegationChain(capabilities: DelegatedCapability[]): boolean {
	for (const cap of capabilities) {
		if (!cap.delegation) continue;
		if (cap.delegation.delegationChain.length < 2) return false;
		if (cap.delegation.delegationChain.at(-1) !== cap.delegation.delegatedTo) return false;
	}
	return true;
}

/**
 * Revoke all capabilities in a set that were delegated by a specific principal.
 *
 * Returns the filtered list with revoked capabilities removed.
 * Revocation is transitive: if A delegated to B who delegated to C,
 * revoking A's delegation removes both B's and C's capabilities.
 */
export function revokeDelegationsFrom(
	capabilities: DelegatedCapability[],
	revokingPrincipalId: string,
): DelegatedCapability[] {
	return capabilities.filter((cap) => {
		if (!cap.delegation) return true;
		// Remove if the revoking principal appears anywhere in the chain (transitive revocation)
		return !cap.delegation.delegationChain.includes(revokingPrincipalId);
	});
}
