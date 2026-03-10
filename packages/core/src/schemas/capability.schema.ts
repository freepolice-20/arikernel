import { z } from "zod";
import { CAPABILITY_CLASSES } from "../types/capability.js";
import { taintLabelSchema } from "./tool-call.schema.js";

const capabilityConstraintSchema = z.object({
	allowedHosts: z.array(z.string()).optional(),
	allowedPaths: z.array(z.string()).optional(),
	allowedCommands: z.array(z.string()).optional(),
	allowedDatabases: z.array(z.string()).optional(),
	parameters: z.record(z.unknown()).optional(),
});

const capabilityLeaseSchema = z.object({
	issuedAt: z.string().datetime(),
	expiresAt: z.string().datetime(),
	maxCalls: z.number().int().positive(),
	callsUsed: z.number().int().min(0),
});

export const capabilityRequestSchema = z.object({
	id: z.string().min(1),
	principalId: z.string().min(1),
	capabilityClass: z.enum(CAPABILITY_CLASSES),
	constraints: capabilityConstraintSchema.optional(),
	taintLabels: z.array(taintLabelSchema),
	justification: z.string().optional(),
	timestamp: z.string().datetime(),
});

export const capabilityGrantSchema = z.object({
	id: z.string().min(1),
	requestId: z.string().min(1),
	principalId: z.string().min(1),
	capabilityClass: z.enum(CAPABILITY_CLASSES),
	constraints: capabilityConstraintSchema,
	lease: capabilityLeaseSchema,
	taintContext: z.array(taintLabelSchema),
	revoked: z.boolean(),
	nonce: z.string().optional(),
});
