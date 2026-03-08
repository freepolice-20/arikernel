/**
 * Shell metacharacters that indicate command chaining, piping, or injection.
 * If any of these appear in a command string, the command is treated as
 * potentially chained and rejected unless the full string is explicitly allowed.
 */
const DANGEROUS_SHELL_PATTERNS = [
	/[;&|`$]/, // chaining (;), background (&), pipe (|), backtick (`), variable expansion ($)
	/\$\(/, // command substitution $(...)
	/>\s*\//, // output redirection to absolute path
	/\|\|/, // logical OR
	/&&/, // logical AND
];

/**
 * Extract the base binary name from a command string.
 * Strips path prefixes (e.g., /usr/bin/git -> git).
 */
function extractBinary(command: string): string {
	const firstToken = command.trim().split(/\s+/)[0];
	// Strip any path prefix to get the bare binary name
	const parts = firstToken.split(/[/\\]/);
	return parts[parts.length - 1];
}

/**
 * Validate a shell command against a structured allowlist.
 *
 * Security checks:
 * 1. The base binary must be in the allowlist
 * 2. The command must not contain shell metacharacters that enable chaining
 *
 * Returns null if the command is allowed, or a reason string if denied.
 */
export function validateCommand(
	command: string,
	allowedCommands: string[],
): string | null {
	if (!command.trim()) {
		return 'Empty command';
	}

	// Check for dangerous shell metacharacters first — injection must be
	// caught even if the binary name is mangled by the metacharacter.
	for (const pattern of DANGEROUS_SHELL_PATTERNS) {
		if (pattern.test(command)) {
			return `Command contains dangerous shell metacharacter: ${command}`;
		}
	}

	const binary = extractBinary(command);

	if (!allowedCommands.includes(binary)) {
		return `Command '${binary}' not in allowed commands: ${allowedCommands.join(', ')}`;
	}

	return null;
}
