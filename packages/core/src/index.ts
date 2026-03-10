export const VERSION = "0.1.0";

export * from "./types/index.js";
export * from "./errors.js";
export { generateId, now } from "./id.js";
export {
	toolCallRequestSchema,
	toolCallSchema,
	toolResultSchema,
	taintLabelSchema,
} from "./schemas/tool-call.schema.js";
export { policyRuleSchema, policySetSchema } from "./schemas/policy.schema.js";
export { firewallConfigSchema, type FirewallConfig } from "./schemas/config.schema.js";
export { capabilityRequestSchema, capabilityGrantSchema } from "./schemas/capability.schema.js";
export {
	createCapabilityToken,
	verifyCapabilityToken,
	serializeCapabilityToken,
	deserializeCapabilityToken,
	generateNonce,
	type SigningAlgorithm,
	type SigningKey,
	type HmacSigningKey,
	type Ed25519SigningKey,
	type SignedCapabilityToken,
	type TokenVerificationResult,
} from "./capability-token.js";
export {
	PRESETS,
	POLICY_SPEC,
	getPreset,
	DEFAULT_CAPABILITIES,
	DEFAULT_POLICIES,
	type Preset,
	type PresetId,
} from "./presets/index.js";
export {
	type DelegationMetadata,
	type DelegatedCapability,
	type DelegationResult,
	delegateCapability,
	createDelegatedPrincipal,
	validateDelegationChain,
	revokeDelegationsFrom,
} from "./capability-delegation.js";
