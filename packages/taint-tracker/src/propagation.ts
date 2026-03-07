import type { TaintLabel } from '@agent-firewall/core';
import { createTaintLabel, mergeTaints } from './labels.js';

export function propagateTaints(
	inputTaints: TaintLabel[],
	callId: string,
): TaintLabel[] {
	if (inputTaints.length === 0) return [];

	const propagated = inputTaints.map((label) =>
		createTaintLabel(label.source, label.origin, label.confidence, callId),
	);

	const toolOutputTaint = createTaintLabel('tool-output', callId, 1.0);

	return mergeTaints(propagated, [toolOutputTaint]);
}
