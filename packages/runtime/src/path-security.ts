import { resolve, normalize } from 'node:path';

/**
 * Resolve and canonicalize a file path for security comparison.
 * Handles ../ traversal, multiple slashes, and relative paths.
 * Returns an absolute, normalized path.
 */
export function canonicalizePath(inputPath: string, cwd?: string): string {
	let p = inputPath;
	if (p.startsWith('~/') || p === '~') {
		const home = process.env.HOME ?? process.env.USERPROFILE ?? '/';
		p = p === '~' ? home : resolve(home, p.slice(2));
	}
	return normalize(resolve(cwd ?? process.cwd(), p));
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
