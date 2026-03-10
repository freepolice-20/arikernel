import type { PolicyRule } from "@arikernel/core";

/**
 * Built-in policy rules used when no --policy flag is provided.
 * Mirrors policies/safe-defaults.yaml but embedded as code so it works
 * from any working directory (including global npm installs).
 */
export const DEFAULT_POLICY: PolicyRule[] = [
	{
		id: "deny-tainted-shell",
		name: "Deny shell commands with untrusted input",
		priority: 10,
		match: { toolClass: "shell", taintSources: ["web", "rag", "email", "retrieved-doc"] },
		decision: "deny",
		reason: "Shell execution with untrusted input is forbidden",
	},
	{
		id: "deny-tainted-file-write",
		name: "Deny file writes with untrusted input",
		priority: 11,
		match: {
			toolClass: "file",
			action: "write",
			taintSources: ["web", "rag", "email", "retrieved-doc"],
		},
		decision: "deny",
		reason: "File writes with untrusted input are forbidden",
	},
	{
		id: "approve-shell",
		name: "Require approval for all shell commands",
		priority: 100,
		match: { toolClass: "shell" },
		decision: "require-approval",
		reason: "Shell commands require human approval",
	},
	{
		id: "approve-file-write",
		name: "Require approval for file writes",
		priority: 110,
		match: { toolClass: "file", action: "write" },
		decision: "require-approval",
		reason: "File writes require human approval",
	},
	{
		id: "allow-http-get",
		name: "Allow HTTP GET requests",
		priority: 200,
		match: { toolClass: "http", action: "get" },
		decision: "allow",
		reason: "HTTP GET requests are allowed (read-only)",
	},
	{
		id: "approve-http-mutate",
		name: "Require approval for HTTP mutations",
		priority: 210,
		match: { toolClass: "http", action: ["post", "put", "patch", "delete"] },
		decision: "require-approval",
		reason: "HTTP mutation requests require human approval",
	},
	{
		id: "allow-file-read",
		name: "Allow file reads",
		priority: 220,
		match: { toolClass: "file", action: "read" },
		decision: "allow",
		reason: "File reads are allowed",
	},
	{
		id: "allow-db-read",
		name: "Allow database queries",
		priority: 230,
		match: { toolClass: "database", action: "query" },
		decision: "allow",
		reason: "Database read queries are allowed",
	},
];
