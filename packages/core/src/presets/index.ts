import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Capability } from '../types/principal.js';
import type { PolicyRule } from '../types/policy.js';

export interface Preset {
	id: string;
	name: string;
	description: string;
	capabilities: Capability[];
	policies: PolicyRule[];
}

export type PresetId = 'safe-research' | 'rag-reader' | 'workspace-assistant' | 'automation-agent';

// ── Load shared policy spec ──────────────────────────────────────────

interface PolicySpec {
	policyFragments: Record<string, PolicyRule>;
	presets: Record<string, {
		id: string;
		name: string;
		description: string;
		capabilities: Capability[];
		policies: (string | PolicyRule)[];
	}>;
	defaults: {
		capabilities: Capability[];
		policies: (string | PolicyRule)[];
	};
}

function loadPolicySpec(): PolicySpec {
	// Walk up from this file to find arikernel-policy.json at the monorepo root
	let dir = dirname(fileURLToPath(import.meta.url));
	for (let i = 0; i < 10; i++) {
		const candidate = resolve(dir, 'arikernel-policy.json');
		try {
			const raw = readFileSync(candidate, 'utf-8');
			return JSON.parse(raw);
		} catch {
			// not found, go up
		}
		const parent = dirname(dir);
		if (parent === dir) break;
		dir = parent;
	}
	throw new Error('Could not find arikernel-policy.json in any parent directory');
}

function resolvePolicy(entry: string | PolicyRule, fragments: Record<string, PolicyRule>): PolicyRule {
	if (typeof entry === 'string') {
		const frag = fragments[entry];
		if (!frag) throw new Error(`Unknown policy fragment: "${entry}"`);
		return frag;
	}
	return entry;
}

function buildPreset(spec: PolicySpec, presetId: string): Preset {
	const raw = spec.presets[presetId];
	if (!raw) throw new Error(`Unknown preset in spec: "${presetId}"`);
	return {
		id: raw.id,
		name: raw.name,
		description: raw.description,
		capabilities: raw.capabilities,
		policies: raw.policies.map((p) => resolvePolicy(p, spec.policyFragments)),
	};
}

const spec = loadPolicySpec();

// ── Presets ──────────────────────────────────────────────────────────

export const PRESETS: Record<PresetId, Preset> = {
	'safe-research': buildPreset(spec, 'safe-research'),
	'rag-reader': buildPreset(spec, 'rag-reader'),
	'workspace-assistant': buildPreset(spec, 'workspace-assistant'),
	'automation-agent': buildPreset(spec, 'automation-agent'),
};

export function getPreset(id: PresetId): Preset {
	const preset = PRESETS[id];
	if (!preset) {
		throw new Error(`Unknown preset: "${id}". Available: ${Object.keys(PRESETS).join(', ')}`);
	}
	return preset;
}

// ── Zero-config defaults ─────────────────────────────────────────────

export const DEFAULT_CAPABILITIES: Capability[] = spec.defaults.capabilities;

export const DEFAULT_POLICIES: PolicyRule[] = spec.defaults.policies.map(
	(p) => resolvePolicy(p, spec.policyFragments),
);
