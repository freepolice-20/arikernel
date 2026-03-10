import type { PolicyRule } from './policy.js';
import type { TaintLabel } from './taint.js';
import type { ToolClass } from './principal.js';

export const CAPABILITY_CLASSES = [
	'http.read',
	'http.write',
	'shell.exec',
	'database.read',
	'database.write',
	'file.read',
	'file.write',
] as const;

export type CapabilityClass = (typeof CAPABILITY_CLASSES)[number];

export interface CapabilityClassMapping {
	toolClass: ToolClass;
	actions: string[];
}

export const CAPABILITY_CLASS_MAP: Record<CapabilityClass, CapabilityClassMapping> = {
	'http.read': { toolClass: 'http', actions: ['get', 'head', 'options'] },
	'http.write': { toolClass: 'http', actions: ['post', 'put', 'patch', 'delete'] },
	'shell.exec': { toolClass: 'shell', actions: ['exec'] },
	'database.read': { toolClass: 'database', actions: ['query'] },
	'database.write': { toolClass: 'database', actions: ['exec', 'mutate'] },
	'file.read': { toolClass: 'file', actions: ['read'] },
	'file.write': { toolClass: 'file', actions: ['write'] },
};

/**
 * Inverse lookup: (toolClass, action) → CapabilityClass.
 *
 * Built from CAPABILITY_CLASS_MAP so all classification stays in one place.
 * Actions are stored lowercase; callers' input is lowercased before lookup.
 */
const INVERSE_MAP = new Map<string, CapabilityClass>();
for (const [capClass, mapping] of Object.entries(CAPABILITY_CLASS_MAP) as [CapabilityClass, CapabilityClassMapping][]) {
	for (const action of mapping.actions) {
		INVERSE_MAP.set(`${mapping.toolClass}:${action}`, capClass);
	}
}

/**
 * Derive a CapabilityClass from a toolClass + action pair.
 *
 * Returns the matching capability class from CAPABILITY_CLASS_MAP,
 * or falls back to `${toolClass}.write` for unknown actions
 * (fail-closed: unknown actions are treated as writes).
 */
export function deriveCapabilityClass(toolClass: string, action: string): CapabilityClass {
	const key = `${toolClass}:${action.toLowerCase()}`;
	return INVERSE_MAP.get(key) ?? (`${toolClass}.write` as CapabilityClass);
}

export interface CapabilityConstraint {
	allowedHosts?: string[];
	allowedPaths?: string[];
	allowedCommands?: string[];
	allowedDatabases?: string[];
	parameters?: Record<string, unknown>;
}

export interface CapabilityLease {
	issuedAt: string;
	expiresAt: string;
	maxCalls: number;
	callsUsed: number;
}

export interface CapabilityRequest {
	id: string;
	principalId: string;
	capabilityClass: CapabilityClass;
	constraints?: CapabilityConstraint;
	taintLabels: TaintLabel[];
	justification?: string;
	timestamp: string;
}

export interface CapabilityGrant {
	id: string;
	requestId: string;
	principalId: string;
	capabilityClass: CapabilityClass;
	constraints: CapabilityConstraint;
	lease: CapabilityLease;
	taintContext: TaintLabel[];
	revoked: boolean;
}

export interface IssuanceDecision {
	requestId: string;
	granted: boolean;
	grant?: CapabilityGrant;
	reason: string;
	matchedRule?: PolicyRule;
	taintLabels: TaintLabel[];
	timestamp: string;
}
