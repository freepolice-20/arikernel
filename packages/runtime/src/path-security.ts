import { existsSync, realpathSync } from 'node:fs';
import { resolve, normalize } from 'node:path';

/**
 * Resolve and canonicalize a file path for security comparison.
 * Handles ../ traversal, multiple slashes, relative paths, and symlinks (CWE-59).
 *
 * If the path exists on disk, realpathSync is used to resolve symlinks.
 * This prevents symlink-based bypass of path allowlists.
 */
export function canonicalizePath(inputPath: string, cwd?: string): string {
	let p = inputPath;
	if (p.startsWith('~/') || p === '~') {
		const home = process.env.HOME ?? process.env.USERPROFILE ?? '/';
		p = p === '~' ? home : resolve(home, p.slice(2));
	}
	const normalized = normalize(resolve(cwd ?? process.cwd(), p));

	// Resolve symlinks if the path exists (CWE-59 protection)
	try {
		if (existsSync(normalized)) {
			return realpathSync(normalized);
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
		if (pattern.endsWith('/**')) {
			const base = canonicalizePath(pattern.slice(0, -3), cwd);
			return canonical === base || canonical.startsWith(base + (process.platform === 'win32' ? '\\' : '/'));
		}
		const canonicalPattern = canonicalizePath(pattern, cwd);
		return canonical === canonicalPattern;
	});

	return { allowed, canonicalPath: canonical };
}
