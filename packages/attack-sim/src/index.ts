export { runSimulation, type SimScenario, type SimResult } from "./runner.js";
export { generateReport } from "./report.js";
export {
	runInteractive,
	ATTACK_TYPES,
	DEFAULT_AUDIT_DB,
	type AttackType,
	type InteractiveResult,
	type InteractiveOptions,
} from "./interactive.js";
export { DEFAULT_POLICY } from "./default-policy.js";
export {
	simulateAttack,
	simulateAll,
	type AttackScenario,
	type AttackResult,
	type AttackStep,
	type StepVerdict,
	type SimAgent,
	type SimulateAttackOptions,
} from "./simulate.js";

// Scenario collections for direct access
export { ssrfScenarios } from "./scenarios/ssrf.js";
export { filesystemTraversalScenarios } from "./scenarios/filesystem-traversal.js";
export { toolEscalationScenarios } from "./scenarios/tool-escalation.js";
export { multiStepExfiltrationScenarios } from "./scenarios/multi-step-exfiltration.js";
export { promptInjectionScenarios } from "./scenarios/prompt-injection.js";
export { dataExfiltrationScenarios } from "./scenarios/data-exfiltration.js";
export { toolMisuseScenarios } from "./scenarios/tool-misuse.js";
export { privilegeEscalationScenarios } from "./scenarios/privilege-escalation.js";
