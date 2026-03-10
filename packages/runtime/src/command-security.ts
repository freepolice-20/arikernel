import { containsDangerousUnicode, normalizeInput } from "./unicode-safety.js";

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
 * Trusted binary locations. Commands with explicit paths must resolve
 * to one of these prefixes, preventing /tmp/evil/git from being treated as "git".
 */
const TRUSTED_PATH_PREFIXES = [
	"/usr/bin/",
	"/usr/local/bin/",
	"/bin/",
	"/sbin/",
	"/usr/sbin/",
	// Windows common locations
	"C:\\Windows\\System32\\",
	"C:\\Windows\\",
	"C:\\Program Files\\",
	"C:\\Program Files (x86)\\",
];

/**
 * Extract the base binary name from a command string.
 * If an explicit path is provided, validates it against trusted locations.
 * Returns null with a reason if the path is untrusted.
 */
function extractBinary(command: string): { binary: string; error?: string } {
	const firstToken = command.trim().split(/\s+/)[0];
	const hasPath = firstToken.includes("/") || firstToken.includes("\\");

	if (hasPath) {
		// Explicit path provided — validate against trusted locations
		const isTrusted = TRUSTED_PATH_PREFIXES.some((prefix) =>
			firstToken.startsWith(prefix) || firstToken.toLowerCase().startsWith(prefix.toLowerCase()),
		);
		if (!isTrusted) {
			return {
				binary: firstToken,
				error: `Command path '${firstToken}' is not in a trusted location. Use bare binary names (e.g., 'git' not '/tmp/evil/git')`,
			};
		}
	}

	// Strip path prefix to get bare binary name for allowlist check
	const parts = firstToken.split(/[/\\]/);
	return { binary: parts[parts.length - 1] };
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
export function validateCommand(command: string, allowedCommands: string[]): string | null {
	if (!command.trim()) {
		return "Empty command";
	}

	// SECURITY: Reject inputs with invisible Unicode characters (zero-width, bidi overrides)
	// that could be used to visually disguise malicious commands.
	if (containsDangerousUnicode(command)) {
		return `Command contains dangerous invisible Unicode characters: ${command}`;
	}

	// SECURITY: Normalize to NFKC before metacharacter check.
	// Prevents bypass via fullwidth characters (＄ → $, ； → ;).
	const normalized = normalizeInput(command);

	// Check for dangerous shell metacharacters first — injection must be
	// caught even if the binary name is mangled by the metacharacter.
	for (const pattern of DANGEROUS_SHELL_PATTERNS) {
		if (pattern.test(normalized)) {
			return `Command contains dangerous shell metacharacter: ${command}`;
		}
	}

	const { binary, error } = extractBinary(normalized);

	if (error) {
		return error;
	}

	if (!allowedCommands.includes(binary)) {
		return `Command '${binary}' not in allowed commands: ${allowedCommands.join(", ")}`;
	}

	return null;
}
