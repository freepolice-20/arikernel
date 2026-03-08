import type { ToolCallRequest, ToolResult, IssuanceDecision, CapabilityClass, TaintLabel } from '@arikernel/core';
import { ToolCallDeniedError } from '@arikernel/core';
import type { Firewall } from '@arikernel/runtime';

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
		const capClass = (opts?.capabilityClass ??
			`${toolClass}.${isReadAction(action) ? 'read' : 'write'}`) as CapabilityClass;

		const grant: IssuanceDecision = firewall.requestCapability(capClass);

		if (!grant.granted) {
			throw new ToolCallDeniedError(
				{
					toolClass,
					action,
					parameters,
					taintLabels: opts?.taintLabels ?? [],
				} as any,
				{
					verdict: 'deny',
					reason: grant.reason ?? 'Capability denied',
					matchedRule: null,
					taintLabels: grant.taintLabels ?? [],
				} as any,
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

function isReadAction(action: string): boolean {
	return ['get', 'read', 'query', 'list', 'search', 'fetch'].includes(action);
}

/**
 * Tool mapping for protectTools().
 */
export interface ToolMapEntry {
	toolClass: string;
	action: string;
	taintLabels?: TaintLabel[];
}

/**
 * Wraps an entire tool map so every tool call goes through AriKernel enforcement.
 *
 * This is the universal integration primitive. Any agent system that executes
 * tools as functions can use this to add AriKernel enforcement:
 *
 * ```ts
 * const tools = protectTools(firewall, {
 *   web_search:  { toolClass: "http", action: "get" },
 *   read_file:   { toolClass: "file", action: "read" },
 *   run_command: { toolClass: "shell", action: "exec" },
 * });
 *
 * // Execute by name — same interface regardless of model or framework
 * await tools.web_search({ url: "https://example.com" });
 * await tools.read_file({ path: "./data/config.json" });
 * ```
 */
export function protectTools(
	firewall: Firewall,
	mappings: Record<string, ToolMapEntry>,
): Record<string, ProtectedTool> {
	const result: Record<string, ProtectedTool> = {};
	for (const [name, entry] of Object.entries(mappings)) {
		const opts: WrapToolOptions | undefined = entry.taintLabels
			? { taintLabels: entry.taintLabels }
			: undefined;
		result[name] = wrapTool(firewall, entry.toolClass, entry.action, opts);
	}
	return result;
}
