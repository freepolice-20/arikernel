import type { TaintLabel, TaintSource } from './taint.js';
import type { ToolClass } from './principal.js';

export type DecisionVerdict = 'allow' | 'deny' | 'require-approval';

export interface ParameterMatcher {
	pattern?: string;
	in?: string[];
	notIn?: string[];
}

export interface PolicyMatch {
	toolClass?: ToolClass | ToolClass[];
	action?: string | string[];
	principalId?: string;
	taintSources?: TaintSource[];
	parameters?: Record<string, ParameterMatcher>;
}

export interface PolicyRule {
	id: string;
	name: string;
	description?: string;
	priority: number;
	match: PolicyMatch;
	decision: DecisionVerdict;
	reason: string;
	tags?: string[];
}

export interface PolicySet {
	name: string;
	version: string;
	rules: PolicyRule[];
}

export interface Decision {
	verdict: DecisionVerdict;
	matchedRule: PolicyRule | null;
	reason: string;
	taintLabels: TaintLabel[];
	timestamp: string;
}
