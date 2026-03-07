import { z } from 'zod';
import { TOOL_CLASSES } from '../types/principal.js';

const capabilityConstraintsSchema = z.object({
	allowedPaths: z.array(z.string()).optional(),
	allowedHosts: z.array(z.string()).optional(),
	allowedCommands: z.array(z.string()).optional(),
	allowedDatabases: z.array(z.string()).optional(),
	maxCallsPerMinute: z.number().int().positive().optional(),
});

const capabilitySchema = z.object({
	toolClass: z.enum(TOOL_CLASSES),
	actions: z.array(z.string()).optional(),
	constraints: capabilityConstraintsSchema.optional(),
});

const principalConfigSchema = z.object({
	name: z.string().min(1),
	capabilities: z.array(capabilitySchema),
});

export const firewallConfigSchema = z.object({
	principal: principalConfigSchema,
	policies: z.union([z.string(), z.array(z.any())]),
	auditLog: z.string().default('./audit.db'),
});

export type FirewallConfig = z.infer<typeof firewallConfigSchema>;
