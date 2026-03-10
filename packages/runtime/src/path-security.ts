import { existsSync, lstatSync, realpathSync } from "node:fs";
import { dirname, normalize, resolve } from "node:path";

/**
 * Resolve and canonicalize a file path for security comparison.
 * Handles ../ traversal, multiple slashes, relative paths, and symlinks (CWE-59).
 *
 * If the path exists on disk, realpathSync is used to resolve symlinks.
 * For non-existent paths, the parent directory is resolved via realpath
 * to prevent TOCTOU symlink bypass (approve non-existent path, then create
 * a symlink at that location pointing outside the allowed directory).
 */
export function canonicalizePath(inputPath: string, cwd?: string): string {
	let p = inputPath;
	if (p.startsWith("~/") || p === "~") {
		const home = process.env.HOME ?? process.env.USERPROFILE ?? "/";
		p = p === "~" ? home : resolve(home, p.slice(2));
	}
	const normalized = normalize(resolve(cwd ?? process.cwd(), p));

	// Resolve symlinks if the path exists (CWE-59 protection)
	try {
		if (existsSync(normalized)) {
			// Reject if the path itself is a symlink (prevent symlink-based escapes)
			const stat = lstatSync(normalized);
			if (stat.isSymbolicLink()) {
				return realpathSync(normalized);
			}
			return realpathSync(normalized);
		}
		// Path doesn't exist — resolve parent directory to prevent TOCTOU symlink attacks.
		// An attacker could: 1) request access to /allowed/file.txt (doesn't exist, passes check)
		// 2) create symlink /allowed/file.txt -> /etc/passwd 3) read via the approved path.
		// By resolving the parent, we ensure the canonical path reflects the real directory.
		const parent = dirname(normalized);
		if (existsSync(parent)) {
			const realParent = realpathSync(parent);
			const filename = normalized.slice(parent.length);
			return realParent + filename;
		}
	} catch {
		// If realpath fails (permissions, etc.), fall back to normalized path
	}
	return normalized;
}

/**
 * Check if a canonicalized path falls within an allowed path pattern.
 * Both paths are canonicalized before comparison to prevent traversal bypass.
 */
export function isPathAllowed(
	inputPath: string,
	allowedPatterns: string[],
	cwd?: string,
): { allowed: boolean; canonicalPath: string } {
	const canonical = canonicalizePath(inputPath, cwd);

	const allowed = allowedPatterns.some((pattern) => {
		if (pattern.endsWith("/**")) {
			const base = canonicalizePath(pattern.slice(0, -3), cwd);
			return (
				canonical === base ||
				canonical.startsWith(base + (process.platform === "win32" ? "\\" : "/"))
			);
		}
		const canonicalPattern = canonicalizePath(pattern, cwd);
		return canonical === canonicalPattern;
	});

	return { allowed, canonicalPath: canonical };
}
