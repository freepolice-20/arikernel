import { z } from 'zod';
import { TAINT_SOURCES } from '../types/taint.js';
import { TOOL_CLASSES } from '../types/principal.js';

const toolClassOrArray = z.union([z.enum(TOOL_CLASSES), z.array(z.enum(TOOL_CLASSES))]);
const stringOrArray = z.union([z.string(), z.array(z.string())]);
const decisionVerdict = z.enum(['allow', 'deny', 'require-approval']);

const parameterMatcherSchema = z.object({
	pattern: z.string().optional(),
	in: z.array(z.string()).optional(),
	notIn: z.array(z.string()).optional(),
});

const policyMatchSchema = z.object({
	toolClass: toolClassOrArray.optional(),
	action: stringOrArray.optional(),
	principalId: z.string().optional(),
	taintSources: z.array(z.enum(TAINT_SOURCES)).optional(),
	parameters: z.record(parameterMatcherSchema).optional(),
});

export const policyRuleSchema = z.object({
	id: z.string().min(1),
	name: z.string().min(1),
	description: z.string().optional(),
	priority: z.number().int().min(0).max(999),
	match: policyMatchSchema,
	decision: decisionVerdict,
	reason: z.string().min(1),
	tags: z.array(z.string()).optional(),
});

export const policySetSchema = z.object({
	name: z.string().min(1),
	version: z.string().min(1),
	rules: z.array(policyRuleSchema),
});
