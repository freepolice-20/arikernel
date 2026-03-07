import { exec } from 'node:child_process';
import type { ToolCall, ToolResult } from '@arikernel/core';
import type { ToolExecutor } from './base.js';
import { DEFAULT_TIMEOUT_MS, makeResult } from './base.js';

export class ShellExecutor implements ToolExecutor {
	readonly toolClass = 'shell';

	async execute(toolCall: ToolCall): Promise<ToolResult> {
		const start = Date.now();
		const { command, cwd } = toolCall.parameters as {
			command: string;
			cwd?: string;
		};

		try {
			const { stdout, stderr } = await execPromise(command, {
				timeout: DEFAULT_TIMEOUT_MS,
				cwd: cwd ?? process.cwd(),
				maxBuffer: 5 * 1024 * 1024,
			});

			const result = makeResult(toolCall.id, true, start, { stdout, stderr });
			return { ...result, taintLabels: [] };
		} catch (err) {
			const error = err instanceof Error ? err.message : String(err);
			const result = makeResult(toolCall.id, false, start, undefined, error);
			return { ...result, taintLabels: [] };
		}
	}
}

function execPromise(
	command: string,
	options: { timeout: number; cwd: string; maxBuffer: number },
): Promise<{ stdout: string; stderr: string }> {
	return new Promise((resolve, reject) => {
		exec(command, options, (error, stdout, stderr) => {
			if (error) {
				reject(new Error(`${error.message}\nstderr: ${stderr}`));
			} else {
				resolve({ stdout, stderr });
			}
		});
	});
}
