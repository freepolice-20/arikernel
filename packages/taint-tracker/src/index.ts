export { TaintTracker } from "./tracker.js";
export { createTaintLabel, hasTaint, hasAnyTaint, mergeTaints } from "./labels.js";
export { propagateTaints } from "./propagation.js";
export { scanForInjection } from "./content-scanner.js";
export type { InjectionSignal } from "./content-scanner.js";
