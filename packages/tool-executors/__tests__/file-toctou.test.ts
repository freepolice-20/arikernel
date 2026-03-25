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

describe("FileExecutor TOCTOU mitigation", () => {
	let tmpDir: string;
	const executor = new FileExecutor();
	const origRoot = process.env.FILE_EXECUTOR_ROOT;

	beforeAll(async () => {
		tmpDir = await mkdtemp(path.join(tmpdir(), "arikernel-file-test-"));
		process.env.FILE_EXECUTOR_ROOT = tmpDir;
		await writeFile(path.join(tmpDir, "allowed.txt"), "safe content");
	});

	afterAll(async () => {
		if (origRoot === undefined) {
			process.env.FILE_EXECUTOR_ROOT = undefined;
		} else {
			process.env.FILE_EXECUTOR_ROOT = origRoot;
		}
		await rm(tmpDir, { recursive: true, force: true });
	});

	it("reads a regular file inside the allowed root", async () => {
		const result = await executor.execute(
			makeToolCall("read", { path: path.join(tmpDir, "allowed.txt") }),
		);
		expect(result.success).toBe(true);
		expect((result.data as { content: string }).content).toBe("safe content");
	});

	it("rejects path traversal via ../", async () => {
		await expect(
			executor.execute(
				makeToolCall("read", { path: path.join(tmpDir, "..", "..", "etc", "passwd") }),
			),
		).rejects.toThrow(/path traversal blocked|outside allowed root/i);
	});

	it("rejects symlinks pointing outside allowed root", async () => {
		const linkPath = path.join(tmpDir, "evil-link");
		let symlinkCreated = false;
		try {
			await symlink("/etc/passwd", linkPath);
			symlinkCreated = true;
		} catch {
			// symlink creation requires elevated privileges on Windows — skip if unavailable
		}
		if (!symlinkCreated) return;

		// On Linux/macOS, O_NOFOLLOW causes the executor to throw.
		// On Windows, the symlink target (/etc/passwd) doesn't exist, so the
		// executor returns success=false with ENOENT — the file is still not read.
		// Both outcomes correctly prevent unauthorized access.
		let threw = false;
		let result: Awaited<ReturnType<typeof executor.execute>> | undefined;
		try {
			result = await executor.execute(makeToolCall("read", { path: linkPath }));
		} catch (e: unknown) {
			threw = true;
			expect((e as Error).message).toMatch(/symlink rejected|ELOOP|path escapes/i);
		}
		if (!threw) {
			// Windows path: symlink resolves to non-existent target — must not succeed
			expect(result?.success).toBe(false);
		}
	});

	it("rejects writes outside allowed root", async () => {
		await expect(
			executor.execute(
				makeToolCall("write", {
					path: path.join(tmpDir, "..", "escape.txt"),
					content: "pwned",
				}),
			),
		).rejects.toThrow(/path traversal blocked|outside allowed root/i);
	});

	it("allows writes inside allowed root", async () => {
		const target = path.join(tmpDir, "new-file.txt");
		const result = await executor.execute(
			makeToolCall("write", { path: target, content: "hello" }),
		);
		expect(result.success).toBe(true);
	});
});
