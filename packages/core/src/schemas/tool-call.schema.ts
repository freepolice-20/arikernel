import { z } from "zod";
import { TOOL_CLASSES } from "../types/principal.js";
import { TAINT_SOURCES } from "../types/taint.js";

export const taintLabelSchema = z.object({
	source: z.enum(TAINT_SOURCES),
	origin: z.string().min(1),
	confidence: z.number().min(0).max(1),
	addedAt: z.string().datetime(),
	propagatedFrom: z.string().optional(),
});

export const toolCallRequestSchema = z.object({
	toolClass: z.enum(TOOL_CLASSES),
	action: z.string().min(1),
	parameters: z.record(z.unknown()),
	taintLabels: z.array(taintLabelSchema).optional(),
	parentCallId: z.string().optional(),
	grantId: z.string().optional(),
});

export const toolCallSchema = z.object({
	id: z.string().min(1),
	runId: z.string().min(1),
	sequence: z.number().int().min(0),
	timestamp: z.string().datetime(),
	principalId: z.string().min(1),
	toolClass: z.enum(TOOL_CLASSES),
	action: z.string().min(1),
	parameters: z.record(z.unknown()),
	taintLabels: z.array(taintLabelSchema),
	parentCallId: z.string().optional(),
	grantId: z.string().optional(),
});

export const toolResultSchema = z.object({
	callId: z.string().min(1),
	success: z.boolean(),
	data: z.unknown().optional(),
	error: z.string().optional(),
	taintLabels: z.array(taintLabelSchema),
	durationMs: z.number().min(0),
});
