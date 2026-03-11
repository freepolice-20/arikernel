import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadScenarioDirectory } from "./scenario-loader.js";
import type { AttackScenario } from "./simulate.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Path to the built-in YAML attack scenarios shipped with @arikernel/attack-sim.
 */
export const BUILTIN_SCENARIOS_DIR = join(__dirname, "..", "scenarios");

/**
 * Load all built-in YAML attack scenarios.
 */
export function loadBuiltinScenarios(): AttackScenario[] {
	return loadScenarioDirectory(BUILTIN_SCENARIOS_DIR);
}
