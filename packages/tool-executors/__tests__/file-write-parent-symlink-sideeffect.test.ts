/**
 * Verifies that file writes cannot create side effects outside the allowed root
 * when a parent directory component is a symlink that escapes containment.
 *
 * The fix validates the parent directory's realpath BEFORE open(O_CREAT), so no
 * file is ever created outside root — even as a transient side effect.
 */

import { existsSync } from "node:fs";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { ToolCall } from "@arikernel/core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { FileExecutor } from "../src/file.js";

function makeToolCall(action: string, params: Record<string, unknown>): ToolCall {
	return {
		id: "test-1",
		toolName: "file",
		toolClass: "file",
		action,
		parameters: params,
		timestamp: new Date().toISOString(),
	};
}

describe("FileExecutor write: parent symlink escape prevention", () => {
	let allowedRoot: string;
	let outsideDir: string;
	const executor = new FileExecutor();
	const origRoot = process.env.FILE_EXECUTOR_ROOT;

	beforeAll(async () => {
		// Create two separate temp directories:
		// allowedRoot — the FILE_EXECUTOR_ROOT
		// outsideDir — a directory outside the root (the escape target)
		allowedRoot = await mkdtemp(path.join(tmpdir(), "arikernel-root-"));
		outsideDir = await mkdtemp(path.join(tmpdir(), "arikernel-outside-"));
		process.env.FILE_EXECUTOR_ROOT = allowedRoot;
	});

	afterAll(async () => {
		if (origRoot === undefined) {
			process.env.FILE_EXECUTOR_ROOT = undefined;
		} else {
			process.env.FILE_EXECUTOR_ROOT = origRoot;
		}
		await rm(allowedRoot, { recursive: true, force: true });
		await rm(outsideDir, { recursive: true, force: true });
	});

	it("blocks write when parent dir is a symlink escaping allowed root — no file created", async () => {
		// Create a symlink inside allowedRoot that points to outsideDir
		const symlinkDir = path.join(allowedRoot, "escape-link");
		try {
			await symlink(outsideDir, symlinkDir, "dir");
		} catch {
			// Symlink creation may require privileges on Windows — skip
			return;
		}

		// Attempt to write to allowedRoot/escape-link/pwned.txt
		// The resolved path looks like it's inside allowedRoot, but the
		// realpath of the parent goes to outsideDir.
		const escapedTarget = path.join(symlinkDir, "pwned.txt");
		const outsideTarget = path.join(outsideDir, "pwned.txt");

		const result = await executor.execute(
			makeToolCall("write", { path: escapedTarget, content: "exfiltrated" }),
		);

		expect(result.success).toBe(false);
		expect(result.error).toMatch(/parent directory escapes|path escapes|symlink/i);

		// Critical assertion: no file should have been created outside root
		expect(existsSync(outsideTarget)).toBe(false);
	});

	it("allows valid writes inside the allowed root", async () => {
		const target = path.join(allowedRoot, "legitimate.txt");
		const result = await executor.execute(
			makeToolCall("write", { path: target, content: "safe content" }),
		);
		expect(result.success).toBe(true);
		expect(existsSync(target)).toBe(true);
	});

	it("allows writes in a real subdirectory inside the allowed root", async () => {
		const subdir = path.join(allowedRoot, "subdir");
		await mkdir(subdir, { recursive: true });
		const target = path.join(subdir, "nested.txt");
		const result = await executor.execute(
			makeToolCall("write", { path: target, content: "nested content" }),
		);
		expect(result.success).toBe(true);
		expect(existsSync(target)).toBe(true);
	});

	it("reads still work correctly inside the allowed root", async () => {
		await writeFile(path.join(allowedRoot, "readable.txt"), "read me");
		const result = await executor.execute(
			makeToolCall("read", { path: path.join(allowedRoot, "readable.txt") }),
		);
		expect(result.success).toBe(true);
		expect((result.data as { content: string }).content).toBe("read me");
	});
});
