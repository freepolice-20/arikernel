/**
 * OpenClaw (formerly Moltbot, originally Clawdbot) compatibility layer for AriKernel.
 *
 * Wraps OpenClaw-style skill/command execution at the tool boundary so
 * AriKernel can enforce security policies on every action. This is the
 * thinnest stable seam: intercept skill execution before the actual
 * handler runs, without requiring changes to OpenClaw internals.
 *
 * Seam: skill/tool wrapper boundary
 * Support level: experimental compatibility layer
 *
 * Usage:
 *
 * ```ts
 * import { createFirewall } from "@arikernel/runtime";
 * import { OpenClawAdapter } from "@arikernel/adapters/openclaw";
 *
 * const firewall = createFirewall({ ... });
 * const adapter = new OpenClawAdapter(firewall);
 *
 * adapter.registerSkill("web_search", "http", "get", searchHandler);
 * adapter.registerSkill("read_file", "file", "read", readHandler);
 *
 * // Execute through AriKernel enforcement
 * const result = await adapter.executeSkill("web_search", { query: "hello" });
 * ```
 */
import type { TaintLabel, ToolResult } from '@arikernel/core';
import { ToolCallDeniedError } from '@arikernel/core';
import type { Firewall } from '@arikernel/runtime';
import { wrapTool, type FrameworkAdapter, type WrapToolOptions } from './adapter.js';

/** Metadata for a registered OpenClaw skill. */
export interface OpenClawSkillRegistration {
	toolClass: string;
	action: string;
	description?: string;
	taintLabels?: TaintLabel[];
}

/** Handler function for an OpenClaw skill. */
export type OpenClawSkillHandler = (args: Record<string, unknown>) => unknown | Promise<unknown>;

/**
 * Compatibility adapter for OpenClaw skill/command execution.
 *
 * Maps OpenClaw skill names to AriKernel toolClass/action pairs and
 * routes every execution through the firewall enforcement pipeline:
 * capability checks, policy evaluation, taint tracking, behavioral
 * detection, and audit logging.
 */
export class OpenClawAdapter implements FrameworkAdapter {
	readonly framework = 'openclaw';
	private readonly firewall: Firewall;
	private readonly skills = new Map<
		string,
		{ wrapped: (args: Record<string, unknown>) => Promise<ToolResult>; handler: OpenClawSkillHandler }
	>();
	private readonly metadata = new Map<string, { description: string; toolClass: string; action: string }>();

	constructor(firewall: Firewall) {
		this.firewall = firewall;
	}

	/**
	 * Register an OpenClaw skill with AriKernel protection.
	 *
	 * The handler is the original skill implementation. It will only
	 * execute if AriKernel's security pipeline approves the call.
	 */
	registerSkill(
		skillName: string,
		toolClass: string,
		action: string,
		handler: OpenClawSkillHandler,
		opts?: { description?: string; taintLabels?: TaintLabel[] },
	): this {
		const wrapOpts: WrapToolOptions | undefined = opts?.taintLabels
			? { taintLabels: opts.taintLabels }
			: undefined;

		// Register a stub executor so the firewall pipeline can run
		this.firewall.registerExecutor({
			toolClass,
			async execute(toolCall) {
				return {
					callId: toolCall.id,
					success: true,
					data: null,
					durationMs: 0,
					taintLabels: [],
				};
			},
		});

		const wrapped = wrapTool(this.firewall, toolClass, action, wrapOpts);
		this.skills.set(skillName, { wrapped, handler });
		this.metadata.set(skillName, {
			description: opts?.description ?? '',
			toolClass,
			action,
		});
		return this;
	}

	/**
	 * Execute a registered skill through AriKernel enforcement.
	 *
	 * The security pipeline runs first. If the call is denied, a
	 * ToolCallDeniedError is thrown and the handler never executes.
	 */
	async executeSkill(
		skillName: string,
		args: Record<string, unknown> = {},
	): Promise<unknown> {
		const entry = this.skills.get(skillName);
		if (!entry) {
			throw new Error(
				`Unknown OpenClaw skill "${skillName}". ` +
				`Registered: ${[...this.skills.keys()].join(', ')}`,
			);
		}

		// Route through firewall — throws ToolCallDeniedError if blocked
		await entry.wrapped(args);

		// Security passed — execute the original handler
		return entry.handler(args);
	}

	/** List registered skill names. */
	get skillNames(): string[] {
		return [...this.skills.keys()];
	}

	/** Return metadata for all registered skills. */
	getSkillInfo(): Array<{ name: string; description: string; toolClass: string; action: string }> {
		return [...this.metadata.entries()].map(([name, meta]) => ({
			name,
			...meta,
		}));
	}

	/**
	 * Not directly applicable — OpenClaw agents are external.
	 * Use `registerSkill()` + `executeSkill()` instead.
	 */
	protect(_agent: unknown): never {
		throw new Error(
			'OpenClawAdapter.protect() is not supported. ' +
			'Use adapter.registerSkill(name, toolClass, action, handler) to register skills, ' +
			'then adapter.executeSkill(name, args) to call them through AriKernel.',
		);
	}
}
