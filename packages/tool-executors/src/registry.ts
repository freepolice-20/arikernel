import type { ToolClass } from '@agent-firewall/core';
import type { ToolExecutor } from './base.js';
import { DatabaseExecutor } from './database.js';
import { FileExecutor } from './file.js';
import { HttpExecutor } from './http.js';
import { ShellExecutor } from './shell.js';

export class ExecutorRegistry {
	private executors = new Map<string, ToolExecutor>();

	constructor() {
		this.register(new HttpExecutor());
		this.register(new FileExecutor());
		this.register(new ShellExecutor());
		this.register(new DatabaseExecutor());
	}

	register(executor: ToolExecutor): void {
		this.executors.set(executor.toolClass, executor);
	}

	get(toolClass: ToolClass): ToolExecutor | undefined {
		return this.executors.get(toolClass);
	}

	has(toolClass: ToolClass): boolean {
		return this.executors.has(toolClass);
	}
}
