import { mkdirSync } from "node:fs";
import { join } from "node:path";
import type { Capability, PolicyRule, SigningKey } from "@arikernel/core";
import { getPreset } from "@arikernel/core";
import type { PresetId } from "@arikernel/core";
import { type Firewall, createFirewall } from "@arikernel/runtime";
import type { RunStatePolicy, SecurityMode } from "@arikernel/runtime";
import {
	DatabaseExecutor,
	FileExecutor,
	HttpExecutor,
	RetrievalExecutor,
	ShellExecutor,
} from "@arikernel/tool-executors";

const ALL_TOOL_CLASSES = ["http", "file", "shell", "database", "retrieval"] as const;

function defaultCapabilities(): Capability[] {
	return ALL_TOOL_CLASSES.map((toolClass) => ({ toolClass }));
}

function attachExecutors(firewall: Firewall): void {
	firewall.registerExecutor(new HttpExecutor());
	firewall.registerExecutor(new FileExecutor());
	firewall.registerExecutor(new ShellExecutor());
	firewall.registerExecutor(new DatabaseExecutor());
	firewall.registerExecutor(new RetrievalExecutor());
}

export interface RegistryConfig {
	policies: string | PolicyRule[];
	capabilities?: Capability[];
	runStatePolicy?: RunStatePolicy;
	signingKey?: SigningKey;
	securityMode?: SecurityMode;
}

/**
 * Resolve a SidecarConfig into the concrete values the registry needs.
 * Preset provides defaults; explicit config overrides preset values.
 */
export function resolveRegistryConfig(config: {
	policy?: string | PolicyRule[];
	preset?: PresetId;
	capabilities?: Capability[];
	runStatePolicy?: RunStatePolicy;
	signingKey?: SigningKey;
	securityMode?: SecurityMode;
}): RegistryConfig {
	if (config.preset) {
		const preset = getPreset(config.preset);
		return {
			policies: config.policy ?? preset.policies,
			capabilities: config.capabilities ?? preset.capabilities,
			runStatePolicy: config.runStatePolicy ?? preset.runStatePolicy,
			signingKey: config.signingKey,
			securityMode: config.securityMode,
		};
	}

	if (!config.policy) {
		throw new Error("SidecarConfig requires either 'policy' or 'preset' to be set");
	}

	return {
		policies: config.policy,
		capabilities: config.capabilities,
		runStatePolicy: config.runStatePolicy,
		signingKey: config.signingKey,
		securityMode: config.securityMode,
	};
}

/**
 * Manages one Firewall per principalId. Each principal gets its own run-state,
 * taint graph, and audit DB — enforcing quarantine and behavioral rules independently.
 */
export class PrincipalRegistry {
	private readonly firewalls = new Map<string, Firewall>();
	private readonly auditDir: string;
	private readonly policies: string | PolicyRule[];
	private readonly capabilities: Capability[];
	private readonly runStatePolicy?: RunStatePolicy;
	private readonly signingKey?: SigningKey;
	private readonly securityMode?: SecurityMode;

	constructor(auditDir: string, registryConfig: RegistryConfig) {
		mkdirSync(auditDir, { recursive: true });
		this.auditDir = auditDir;
		this.policies = registryConfig.policies;
		this.capabilities = registryConfig.capabilities ?? defaultCapabilities();
		this.runStatePolicy = registryConfig.runStatePolicy;
		this.signingKey = registryConfig.signingKey;
		this.securityMode = registryConfig.securityMode;
	}

	getOrCreate(principalId: string): Firewall {
		const existing = this.firewalls.get(principalId);
		if (existing) return existing;

		const sanitized = principalId.replace(/[^a-zA-Z0-9_-]/g, "_");
		const auditLog = join(this.auditDir, `${sanitized}.db`);

		const firewall = createFirewall({
			principal: {
				name: principalId,
				capabilities: this.capabilities,
			},
			policies: this.policies,
			auditLog,
			runStatePolicy: this.runStatePolicy,
			signingKey: this.signingKey,
			securityMode: this.securityMode,
		});

		attachExecutors(firewall);
		this.firewalls.set(principalId, firewall);
		return firewall;
	}

	/** Number of firewalls owned by a specific principal (0 or 1 in current model). */
	principalFirewallCount(principalId: string): number {
		return this.firewalls.has(principalId) ? 1 : 0;
	}

	/** Total number of active firewall instances across all principals. */
	get totalFirewallCount(): number {
		return this.firewalls.size;
	}

	/** Check if a principal has an active firewall (without creating one). */
	has(principalId: string): boolean {
		return this.firewalls.has(principalId);
	}

	/** The signing key used for token verification, if configured. */
	getSigningKey(): SigningKey | undefined {
		return this.signingKey;
	}

	/** The security mode for this registry. */
	getSecurityMode(): SecurityMode | undefined {
		return this.securityMode;
	}

	closeAll(): void {
		for (const fw of this.firewalls.values()) {
			try {
				fw.close();
			} catch {
				/* ignore */
			}
		}
		this.firewalls.clear();
	}
}
