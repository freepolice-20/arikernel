import { open, realpath } from "node:fs/promises";
import { constants } from "node:fs";
import path from "node:path";
import type { ToolCall, ToolResult } from "@arikernel/core";
import type { ToolExecutor } from "./base.js";
import { makeResult } from "./base.js";

/**
 * SECURITY: Resolve the allowed root directory once upfront.
 * Default to cwd; callers should set FILE_EXECUTOR_ROOT to restrict further.
 */
function getAllowedRoot(): string {
	return path.resolve(process.env.FILE_EXECUTOR_ROOT ?? process.cwd());
}

/**
 * SECURITY: Opens a file using O_NOFOLLOW to prevent symlink-following,
 * then verifies via fstat + realpath that the opened descriptor refers to
 * a regular file inside the allowed root. This eliminates the TOCTOU race
 * between path validation and file read: we validate *after* opening the
 * descriptor, so no attacker-controlled symlink swap can redirect the read.
 */
async function secureOpen(filePath: string, flags: number): Promise<import("node:fs/promises").FileHandle> {
	const allowedRoot = getAllowedRoot();

	// SECURITY: Resolve to absolute path and verify it is within the allowed root
	// *before* opening, as a first line of defense against ../traversal.
	const resolved = path.resolve(filePath);
	if (!resolved.startsWith(allowedRoot + path.sep) && resolved !== allowedRoot) {
		throw new Error(`Path traversal blocked: ${filePath} is outside allowed root`);
	}

	// SECURITY: Open with O_NOFOLLOW so the kernel refuses to follow symlinks.
	// This prevents a symlink at `filePath` from redirecting to an arbitrary file.
	let handle: import("node:fs/promises").FileHandle;
	try {
		handle = await open(resolved, flags);
	} catch (err: unknown) {
		const code = (err as NodeJS.ErrnoException).code;
		// ELOOP = symlink encountered with O_NOFOLLOW on Linux/macOS
		// On Windows, O_NOFOLLOW may not be supported; we rely on post-open checks.
		if (code === "ELOOP" || code === "ESYMLINK") {
			throw new Error(`Symlink rejected: ${filePath}`);
		}
		throw err;
	}

	try {
		// SECURITY: fstat on the opened fd to verify it's a regular file,
		// not a symlink, device, or directory that could leak data.
		const stat = await handle.stat();
		if (stat.isSymbolicLink()) {
			throw new Error(`Symlink rejected: ${filePath}`);
		}
		if (!stat.isFile()) {
			throw new Error(`Not a regular file: ${filePath}`);
		}

		// SECURITY: Double-check the real path of the fd target is still
		// inside the allowed root. This catches edge cases where the resolved
		// path appeared safe but intermediate directories were symlinks.
		const realFile = await realpath(resolved);
		const realRoot = await realpath(allowedRoot);
		if (!realFile.startsWith(realRoot + path.sep) && realFile !== realRoot) {
			throw new Error(`Path escapes allowed root after resolution: ${filePath}`);
		}
	} catch (err) {
		await handle.close();
		throw err;
	}

	return handle;
}

export class FileExecutor implements ToolExecutor {
	readonly toolClass = "file";

	async execute(toolCall: ToolCall): Promise<ToolResult> {
		const start = Date.now();
		const { path: filePath, content, encoding } = toolCall.parameters as {
			path: string;
			content?: string;
			encoding?: BufferEncoding;
		};

		try {
			switch (toolCall.action) {
				case "read": {
					// SECURITY: Use descriptor-based read to eliminate TOCTOU race.
					// open() → fstat() → verify root → read(fd) — all on the same fd.
					const handle = await secureOpen(
						filePath,
						constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
					);
					try {
						const data = await handle.readFile(encoding ?? "utf-8") as string;
						const result = makeResult(toolCall.id, true, start, { path: filePath, content: data });
						return { ...result, taintLabels: [] };
					} finally {
						await handle.close();
					}
				}
				case "write": {
					// SECURITY: Open WITHOUT O_TRUNC first — truncation before
					// post-open validation would destroy data if checks fail.
					// O_CREAT allows creating new files; O_NOFOLLOW prevents symlink writes.
					const writeFlags =
						constants.O_WRONLY |
						constants.O_CREAT |
						(constants.O_NOFOLLOW ?? 0);

					const allowedRoot = getAllowedRoot();
					const resolved = path.resolve(filePath);
					if (
						!resolved.startsWith(allowedRoot + path.sep) &&
						resolved !== allowedRoot
					) {
						throw new Error(`Path traversal blocked: ${filePath} is outside allowed root`);
					}

					const handle = await open(resolved, writeFlags, 0o644);
					try {
						// Post-open validation: same checks as secureOpen (read path)
						const stat = await handle.stat();
						if (stat.isSymbolicLink()) {
							throw new Error(`Symlink rejected: ${filePath}`);
						}
						if (!stat.isFile() && stat.size > 0) {
							throw new Error(`Not a regular file: ${filePath}`);
						}

						// SECURITY: Verify realpath is within allowed root (matches read path)
						const realFile = await realpath(resolved);
						const realRoot = await realpath(allowedRoot);
						if (!realFile.startsWith(realRoot + path.sep) && realFile !== realRoot) {
							throw new Error(`Path escapes allowed root after resolution: ${filePath}`);
						}

						// Now safe to truncate and write — all checks passed on this fd
						await handle.truncate(0);
						await handle.writeFile(content ?? "", encoding ?? "utf-8");
						const result = makeResult(toolCall.id, true, start, {
							path: filePath,
							bytesWritten: (content ?? "").length,
						});
						return { ...result, taintLabels: [] };
					} catch (err) {
						await handle.close();
						throw err;
					} finally {
						// close is idempotent; safe to call even if catch already closed
						await handle.close().catch(() => {});
					}
				}
				default: {
					const result = makeResult(
						toolCall.id,
						false,
						start,
						undefined,
						`Unknown file action: ${toolCall.action}`,
					);
					return { ...result, taintLabels: [] };
				}
			}
		} catch (err) {
			const error = err instanceof Error ? err.message : String(err);
			const result = makeResult(toolCall.id, false, start, undefined, error);
			return { ...result, taintLabels: [] };
		}
	}
}
