import { access, readFile, writeFile } from "node:fs/promises";
import type { ToolCall, ToolResult } from "@arikernel/core";
import type { ToolExecutor } from "./base.js";
import { makeResult } from "./base.js";

export class FileExecutor implements ToolExecutor {
	readonly toolClass = "file";

	async execute(toolCall: ToolCall): Promise<ToolResult> {
		const start = Date.now();
		const { path, content, encoding } = toolCall.parameters as {
			path: string;
			content?: string;
			encoding?: BufferEncoding;
		};

		try {
			switch (toolCall.action) {
				case "read": {
					await access(path);
					const data = await readFile(path, encoding ?? "utf-8");
					const result = makeResult(toolCall.id, true, start, { path, content: data });
					return { ...result, taintLabels: [] };
				}
				case "write": {
					await writeFile(path, content ?? "", encoding ?? "utf-8");
					const result = makeResult(toolCall.id, true, start, {
						path,
						bytesWritten: (content ?? "").length,
					});
					return { ...result, taintLabels: [] };
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
