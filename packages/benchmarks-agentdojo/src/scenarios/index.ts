import type { ScenarioResult } from "../types.js";
import * as s1 from "./scenario-1-prompt-injection-sensitive-file.js";
import * as s2 from "./scenario-2-prompt-injection-exfiltration.js";
import * as s3 from "./scenario-3-escalation-after-denial.js";
import * as s4 from "./scenario-4-web-taint-sensitive-probe.js";
import * as s5 from "./scenario-5-repeated-sensitive-probe.js";

export interface ScenarioDef {
	id: string;
	name: string;
	attackClass: string;
	run(dbPath: string): Promise<ScenarioResult>;
}

export const SCENARIOS: ScenarioDef[] = [
	{ id: s1.SCENARIO_ID, name: s1.SCENARIO_NAME, attackClass: s1.ATTACK_CLASS, run: s1.run },
	{ id: s2.SCENARIO_ID, name: s2.SCENARIO_NAME, attackClass: s2.ATTACK_CLASS, run: s2.run },
	{ id: s3.SCENARIO_ID, name: s3.SCENARIO_NAME, attackClass: s3.ATTACK_CLASS, run: s3.run },
	{ id: s4.SCENARIO_ID, name: s4.SCENARIO_NAME, attackClass: s4.ATTACK_CLASS, run: s4.run },
	{ id: s5.SCENARIO_ID, name: s5.SCENARIO_NAME, attackClass: s5.ATTACK_CLASS, run: s5.run },
];
