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
		const result = await executor.execute(
			makeToolCall("read", { path: path.join(tmpDir, "..", "..", "etc", "passwd") }),
		);
		expect(result.success).toBe(false);
		expect(result.error).toMatch(/path traversal blocked|outside allowed root/i);
	});

	it("rejects symlinks pointing outside allowed root", async () => {
		const linkPath = path.join(tmpDir, "evil-link");
		try {
			await symlink("/etc/passwd", linkPath);
		} catch {
			// symlink creation may fail on Windows without privileges — skip
			return;
		}
		const result = await executor.execute(makeToolCall("read", { path: linkPath }));
		expect(result.success).toBe(false);
		expect(result.error).toMatch(/symlink rejected|ELOOP|path escapes/i);
	});

	it("rejects writes outside allowed root", async () => {
		const result = await executor.execute(
			makeToolCall("write", {
				path: path.join(tmpDir, "..", "escape.txt"),
				content: "pwned",
			}),
		);
		expect(result.success).toBe(false);
		expect(result.error).toMatch(/path traversal blocked|outside allowed root/i);
	});

	it("allows writes inside allowed root", async () => {
		const target = path.join(tmpDir, "new-file.txt");
		const result = await executor.execute(
			makeToolCall("write", { path: target, content: "hello" }),
		);
		expect(result.success).toBe(true);
	});
});
