import type { ToolCallRequest, ToolResult, IssuanceDecision, CapabilityClass, TaintLabel } from '@arikernel/core';
import { ToolCallDeniedError, generateId, now, deriveCapabilityClass } from '@arikernel/core';
import type { Firewall, Kernel } from '@arikernel/runtime';
import { getDefaultKernel } from '@arikernel/runtime';

/**
 * Base adapter interface for framework integrations.
 *
 * Implementations wrap a specific framework's tool execution so that
 * every call is routed through AriKernel before reaching the actual tool.
 */
export interface FrameworkAdapter<TAgent = unknown> {
	/** Name of the framework (e.g. "langchain", "crewai"). */
	readonly framework: string;

	/**
	 * Wrap an agent's tool execution to route through AriKernel.
	 * Returns the protected agent (may be the same instance, mutated).
	 */
	protect(agent: TAgent): TAgent;
}

/**
 * A tool wrapped with firewall enforcement.
 *
 * This is the core primitive that all adapters use internally.
 * It handles capability request → execution → error handling.
 */
export interface ProtectedTool {
	(parameters: Record<string, unknown>): Promise<ToolResult>;
}

export interface WrapToolOptions {
	/** Capability class to request (e.g. "http.read"). Auto-derived if omitted. */
	capabilityClass?: CapabilityClass;
	/** Taint labels to attach to the request. */
	taintLabels?: TaintLabel[];
}

/**
 * Wraps a tool call so it goes through AriKernel enforcement.
 *
 * This is the universal building block for all framework adapters:
 *
 * ```ts
 * const httpGet = wrapTool(firewall, "http", "get");
 * const result = await httpGet({ url: "https://example.com" });
 * ```
 */
export function wrapTool(
	firewall: Firewall,
	toolClass: string,
	action: string,
	opts?: WrapToolOptions,
): ProtectedTool {
	return async (parameters: Record<string, unknown>) => {
		const capClass = (opts?.capabilityClass ?? deriveCapabilityClass(toolClass, action)) as CapabilityClass;

		const grant: IssuanceDecision = firewall.requestCapability(capClass);

		if (!grant.granted) {
			const ts = now();
			throw new ToolCallDeniedError(
				{
					id: generateId(),
					runId: '',
					sequence: 0,
					timestamp: ts,
					principalId: '',
					toolClass: toolClass as ToolCallRequest['toolClass'],
					action,
					parameters,
					taintLabels: opts?.taintLabels ?? [],
				},
				{
					verdict: 'deny',
					reason: grant.reason ?? 'Capability denied',
					matchedRule: null,
					taintLabels: grant.taintLabels ?? [],
					timestamp: ts,
				},
			);
		}

		const request: ToolCallRequest = {
			toolClass: toolClass as ToolCallRequest['toolClass'],
			action,
			parameters,
			grantId: grant.grant!.id,
			taintLabels: opts?.taintLabels,
		};

		return firewall.execute(request);
	};
}


/**
 * Tool mapping for protectTools().
 */
export interface ToolMapEntry {
	toolClass: string;
	action: string;
	taintLabels?: TaintLabel[];
}

export interface ProtectToolsOptions {
	kernel?: Kernel;
}

/**
 * Wraps an entire tool map so every tool call goes through AriKernel enforcement.
 *
 * Accepts either a Firewall instance (original API) or a tool map with options
 * including a Kernel (new API). If no kernel is provided in the options form,
 * uses the global default kernel.
 *
 * ```ts
 * // Original API — pass a Firewall directly
 * const tools = protectTools(firewall, {
 *   web_search: { toolClass: "http", action: "get" },
 * });
 *
 * // New API — pass a Kernel via options
 * const kernel = createKernel({ preset: "safe-research" });
 * const tools = protectTools({
 *   web_search: { toolClass: "http", action: "get" },
 * }, { kernel });
 *
 * // New API — zero-config (uses global default kernel)
 * const tools = protectTools({
 *   web_search: { toolClass: "http", action: "get" },
 * });
 * ```
 */
export function protectTools(
	firewallOrMappings: Firewall | Record<string, ToolMapEntry>,
	mappingsOrOptions?: Record<string, ToolMapEntry> | ProtectToolsOptions,
): Record<string, ProtectedTool> {
	let firewall: Firewall;
	let mappings: Record<string, ToolMapEntry>;

	if (isFirewall(firewallOrMappings)) {
		// Original API: protectTools(firewall, mappings)
		firewall = firewallOrMappings;
		mappings = mappingsOrOptions as Record<string, ToolMapEntry>;
	} else {
		// New API: protectTools(mappings, options?)
		mappings = firewallOrMappings;
		const opts = (mappingsOrOptions as ProtectToolsOptions | undefined) ?? {};
		const kernel = opts.kernel ?? getDefaultKernel();
		firewall = kernel.createFirewall();
	}

	const result: Record<string, ProtectedTool> = {};
	for (const [name, entry] of Object.entries(mappings)) {
		const opts: WrapToolOptions | undefined = entry.taintLabels
			? { taintLabels: entry.taintLabels }
			: undefined;
		result[name] = wrapTool(firewall, entry.toolClass, entry.action, opts);
	}
	return result;
}

function isFirewall(obj: unknown): obj is Firewall {
	return obj !== null && typeof obj === 'object' && 'execute' in obj && 'requestCapability' in obj;
}
