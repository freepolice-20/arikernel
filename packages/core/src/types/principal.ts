export const TOOL_CLASSES = ['http', 'file', 'shell', 'database', 'browser'] as const;
export type ToolClass = (typeof TOOL_CLASSES)[number];

export interface CapabilityConstraints {
	allowedPaths?: string[];
	allowedHosts?: string[];
	allowedCommands?: string[];
	allowedDatabases?: string[];
	maxCallsPerMinute?: number;
}

export interface Capability {
	toolClass: ToolClass;
	actions?: string[];
	constraints?: CapabilityConstraints;
}

export interface Principal {
	id: string;
	name: string;
	capabilities: Capability[];
}
