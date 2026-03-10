import type { PolicyRule } from "../types/policy.js";
import type { Capability } from "../types/principal.js";
import policySpec from "./policy-spec.json";

export interface Preset {
	id: string;
	name: string;
	description: string;
	capabilities: Capability[];
	policies: PolicyRule[];
	runStatePolicy?: {
		maxDeniedSensitiveActions?: number;
		behavioralRules?: boolean;
	};
}

export type PresetId =
	| "safe-research"
	| "rag-reader"
	| "workspace-assistant"
	| "automation-agent"
	| "safe"
	| "strict"
	| "research"
	| "anti-collusion";

// ── Policy spec types ────────────────────────────────────────────────

interface PolicySpec {
	policyFragments: Record<string, PolicyRule>;
	presets: Record<
		string,
		{
			id: string;
			name: string;
			description: string;
			capabilities: Capability[];
			policies: (string | PolicyRule)[];
			runStatePolicy?: {
				maxDeniedSensitiveActions?: number;
				behavioralRules?: boolean;
			};
		}
	>;
	defaults: {
		capabilities: Capability[];
		policies: (string | PolicyRule)[];
	};
}

const spec = policySpec as unknown as PolicySpec;

/** The full policy spec, available for programmatic access. */
export const POLICY_SPEC = spec;

// ── Helpers ──────────────────────────────────────────────────────────

function resolvePolicy(
	entry: string | PolicyRule,
	fragments: Record<string, PolicyRule>,
): PolicyRule {
	if (typeof entry === "string") {
		const frag = fragments[entry];
		if (!frag) throw new Error(`Unknown policy fragment: "${entry}"`);
		return frag;
	}
	return entry;
}

function buildPreset(s: PolicySpec, presetId: string): Preset {
	const raw = s.presets[presetId];
	if (!raw) throw new Error(`Unknown preset in spec: "${presetId}"`);
	return {
		id: raw.id,
		name: raw.name,
		description: raw.description,
		capabilities: raw.capabilities,
		policies: raw.policies.map((p) => resolvePolicy(p, s.policyFragments)),
		runStatePolicy: raw.runStatePolicy,
	};
}

// ── Presets ──────────────────────────────────────────────────────────

export const PRESETS: Record<PresetId, Preset> = {
	"safe-research": buildPreset(spec, "safe-research"),
	"rag-reader": buildPreset(spec, "rag-reader"),
	"workspace-assistant": buildPreset(spec, "workspace-assistant"),
	"automation-agent": buildPreset(spec, "automation-agent"),
	safe: buildPreset(spec, "safe"),
	strict: buildPreset(spec, "strict"),
	research: buildPreset(spec, "research"),
	"anti-collusion": buildPreset(spec, "anti-collusion"),
};

export function getPreset(id: PresetId): Preset {
	const preset = PRESETS[id];
	if (!preset) {
		throw new Error(`Unknown preset: "${id}". Available: ${Object.keys(PRESETS).join(", ")}`);
	}
	return preset;
}

// ── Zero-config defaults ─────────────────────────────────────────────

export const DEFAULT_CAPABILITIES: Capability[] = spec.defaults.capabilities;

export const DEFAULT_POLICIES: PolicyRule[] = spec.defaults.policies.map((p) =>
	resolvePolicy(p, spec.policyFragments),
);
