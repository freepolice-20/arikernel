import type { TaintLabel, TaintSource } from '@agent-firewall/core';
import { now } from '@agent-firewall/core';

export function createTaintLabel(
	source: TaintSource,
	origin: string,
	confidence = 1.0,
	propagatedFrom?: string,
): TaintLabel {
	return {
		source,
		origin,
		confidence: Math.max(0, Math.min(1, confidence)),
		addedAt: now(),
		propagatedFrom,
	};
}

export function hasTaint(labels: TaintLabel[], source: TaintSource): boolean {
	return labels.some((l) => l.source === source);
}

export function hasAnyTaint(labels: TaintLabel[], sources: TaintSource[]): boolean {
	return sources.some((s) => hasTaint(labels, s));
}

export function mergeTaints(...labelSets: TaintLabel[][]): TaintLabel[] {
	const seen = new Set<string>();
	const merged: TaintLabel[] = [];

	for (const labels of labelSets) {
		for (const label of labels) {
			const key = `${label.source}:${label.origin}`;
			if (!seen.has(key)) {
				seen.add(key);
				merged.push(label);
			}
		}
	}

	return merged;
}
