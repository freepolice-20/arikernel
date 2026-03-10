import { PRESETS, type PresetId, getPreset } from "@arikernel/core";
import { loadPolicyFile } from "@arikernel/policy-engine";

export function runPolicyValidate(filePath: string): void {
	try {
		const rules = loadPolicyFile(filePath);
		console.log(`Policy file is valid: ${filePath}`);
		console.log(`  Rules: ${rules.length}`);

		for (const rule of rules) {
			console.log(`  - [${rule.priority}] ${rule.name} -> ${rule.decision}`);
		}
	} catch (err) {
		console.error(`Policy validation failed: ${err instanceof Error ? err.message : err}`);
		process.exit(1);
	}
}

export function runPolicyList(): void {
	console.log("Available security presets:\n");
	for (const [id, preset] of Object.entries(PRESETS)) {
		const rsp = preset.runStatePolicy;
		const threshold = rsp?.maxDeniedSensitiveActions ?? "—";
		console.log(`  ${id}`);
		console.log(`    ${preset.description}`);
		console.log(
			`    Capabilities: ${preset.capabilities.length}  Policies: ${preset.policies.length}  Quarantine threshold: ${threshold}`,
		);
		console.log();
	}
}

export function runPolicyShow(presetName: string): void {
	try {
		const preset = getPreset(presetName as PresetId);
		console.log(`Preset: ${preset.name} (${preset.id})\n`);
		console.log(`  ${preset.description}\n`);

		console.log("Capabilities:");
		for (const cap of preset.capabilities) {
			const constraints = cap.constraints
				? ` [${Object.entries(cap.constraints)
						.map(([k, v]) => `${k}: ${JSON.stringify(v)}`)
						.join(", ")}]`
				: "";
			console.log(`  ${cap.toolClass}.${cap.actions.join("|")}${constraints}`);
		}

		console.log("\nPolicies:");
		for (const rule of preset.policies) {
			console.log(`  [${rule.priority}] ${rule.name} → ${rule.decision}`);
			if (rule.reason) console.log(`         ${rule.reason}`);
		}

		if (preset.runStatePolicy) {
			console.log("\nRun State Policy:");
			console.log(
				`  Max denied sensitive actions: ${preset.runStatePolicy.maxDeniedSensitiveActions ?? "—"}`,
			);
			console.log(`  Behavioral rules: ${preset.runStatePolicy.behavioralRules ?? false}`);
		}
	} catch (err) {
		console.error(err instanceof Error ? err.message : err);
		process.exit(1);
	}
}
