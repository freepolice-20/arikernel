import type { TaintLabel, TaintSource, ToolCall } from "@arikernel/core";
import { scanForInjection } from "./content-scanner.js";
import { createTaintLabel, hasTaint, mergeTaints } from "./labels.js";
import { propagateTaints } from "./propagation.js";

export class TaintTracker {
	attach(source: TaintSource, origin: string, confidence = 1.0): TaintLabel {
		return createTaintLabel(source, origin, confidence);
	}

	collectInputTaints(toolCall: ToolCall): TaintLabel[] {
		return toolCall.taintLabels ?? [];
	}

	propagate(inputTaints: TaintLabel[], callId: string): TaintLabel[] {
		return propagateTaints(inputTaints, callId);
	}

	merge(...labelSets: TaintLabel[][]): TaintLabel[] {
		return mergeTaints(...labelSets);
	}

	hasTaint(labels: TaintLabel[], source: TaintSource): boolean {
		return hasTaint(labels, source);
	}

	/**
	 * Scan tool output data for prompt injection patterns.
	 * Returns taint labels derived from the content itself.
	 */
	scanOutput(data: unknown, callId: string): TaintLabel[] {
		return scanForInjection(data, callId);
	}
}
