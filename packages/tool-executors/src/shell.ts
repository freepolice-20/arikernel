import { spawn } from "node:child_process";
import type { ToolCall, ToolResult } from "@arikernel/core";
import type { ToolExecutor } from "./base.js";
import { DEFAULT_TIMEOUT_MS, makeResult } from "./base.js";

/**
 * Shell metacharacters that enable command injection when passed through
 * a shell interpreter. Any command string containing these is rejected.
 */
const SHELL_METACHARACTERS = /[;&|`$\n\r\\><(){}\[\]!#~]/;

/**
 * Shells and interpreters that must never be invoked directly.
 * Prevents spawning a shell as the executable, which would
 * re-introduce injection risk even with shell: false.
 */
const BLOCKED_EXECUTABLES = new Set([
	"sh",
	"bash",
	"zsh",
	"fish",
	"csh",
	"tcsh",
	"ksh",
	"dash",
	"cmd",
	"cmd.exe",
	"powershell",
	"powershell.exe",
	"pwsh",
	"pwsh.exe",
]);

/**
 * Validate a command and its arguments for injection safety.
 * Throws if the executable or any argument contains shell metacharacters,
 * or if the executable is a shell interpreter.
 */
export function validateCommand(executable: string, args: readonly string[]): void {
	if (!executable || executable.trim().length === 0) {
		throw new Error("Command executable must not be empty");
	}

	// Block shell interpreters as executables
	const base = executable.split("/").pop()?.split("\\").pop() ?? executable;
	if (BLOCKED_EXECUTABLES.has(base.toLowerCase())) {
		throw new Error(
			`Blocked shell interpreter: "${executable}". Commands must be executed directly, not through a shell.`,
		);
	}

	// Reject metacharacters in executable name
	if (SHELL_METACHARACTERS.test(executable)) {
		throw new Error(`Command executable contains shell metacharacters: "${executable}"`);
	}

	// Reject metacharacters in arguments
	for (let i = 0; i < args.length; i++) {
		if (SHELL_METACHARACTERS.test(args[i])) {
			throw new Error(`Argument ${i} contains shell metacharacters: "${args[i]}"`);
		}
	}
}

/**
 * Parse a legacy command string into [executable, ...args].
 * Only supports simple space-separated commands without quoting.
 * Rejects anything containing shell metacharacters.
 */
export function parseCommandString(command: string): { executable: string; args: string[] } {
	if (SHELL_METACHARACTERS.test(command)) {
		throw new Error(`Command string contains shell metacharacters: "${command}"`);
	}
	const parts = command.trim().split(/\s+/);
	if (parts.length === 0 || parts[0] === "") {
		throw new Error("Command must not be empty");
	}
	return { executable: parts[0], args: parts.slice(1) };
}

export class ShellExecutor implements ToolExecutor {
	readonly toolClass = "shell";

	async execute(toolCall: ToolCall): Promise<ToolResult> {
		const start = Date.now();
		const params = toolCall.parameters as {
			command?: string;
			executable?: string;
			args?: string[];
			cwd?: string;
		};

		try {
			let executable: string;
			let args: string[];

			if (params.executable) {
				// Structured form: executable + args array (preferred)
				executable = params.executable;
				args = params.args ?? [];
			} else if (params.command) {
				// Legacy string form: parse and validate
				const parsed = parseCommandString(params.command);
				executable = parsed.executable;
				args = parsed.args;
			} else {
				throw new Error("Either 'executable' or 'command' parameter is required");
			}

			validateCommand(executable, args);

			const { stdout, stderr } = await spawnSafe(executable, args, {
				timeout: DEFAULT_TIMEOUT_MS,
				cwd: params.cwd ?? process.cwd(),
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

function spawnSafe(
	executable: string,
	args: string[],
	options: { timeout: number; cwd: string; maxBuffer: number },
): Promise<{ stdout: string; stderr: string }> {
	return new Promise((resolve, reject) => {
		const child = spawn(executable, args, {
			cwd: options.cwd,
			shell: false,
			timeout: options.timeout,
			stdio: ["ignore", "pipe", "pipe"],
			env: process.env,
		});

		const stdoutChunks: Buffer[] = [];
		const stderrChunks: Buffer[] = [];
		let totalBytes = 0;

		child.stdout.on("data", (chunk: Buffer) => {
			totalBytes += chunk.length;
			if (totalBytes <= options.maxBuffer) {
				stdoutChunks.push(chunk);
			}
		});

		child.stderr.on("data", (chunk: Buffer) => {
			totalBytes += chunk.length;
			if (totalBytes <= options.maxBuffer) {
				stderrChunks.push(chunk);
			}
		});

		child.on("error", (err) => {
			reject(new Error(`Failed to spawn "${executable}": ${err.message}`));
		});

		child.on("close", (code) => {
			const stdout = Buffer.concat(stdoutChunks).toString("utf8");
			const stderr = Buffer.concat(stderrChunks).toString("utf8");

			if (code !== 0) {
				reject(new Error(`Process exited with code ${code}\nstderr: ${stderr}`));
			} else {
				resolve({ stdout, stderr });
			}
		});
	});
}
