/**
 * Sidecar Guard — Runtime Mediation Layer
 *
 * Installs cooperative runtime guards that intercept dangerous Node.js APIs
 * (fetch, child_process) and route them through the SidecarClient. This
 * helps prevent accidental bypass of sidecar enforcement in the host process.
 *
 * This is NOT OS-level syscall interception. It is a cooperative runtime
 * layer — code that deliberately circumvents the guard (e.g. by caching
 * original references before enableSidecarGuard is called) will not be
 * intercepted. The guard eliminates accidental bypass, not intentional bypass.
 */

import { createRequire } from "node:module";
import type { SidecarClient } from "../client.js";

export interface SidecarGuardOptions {
	/** The SidecarClient to route intercepted calls through. */
	client: SidecarClient;
	/**
	 * Guard fetch (globalThis.fetch). Default: true.
	 * When enabled, outbound HTTP requests are routed through the sidecar's
	 * HTTP executor, which applies policy, taint tracking, and SSRF protection.
	 */
	guardFetch?: boolean;
	/**
	 * Guard child_process (spawn, exec, execFile). Default: true.
	 * When enabled, shell execution attempts throw with a clear error
	 * directing the caller to use the sidecar client instead.
	 */
	guardChildProcess?: boolean;
}

interface GuardState {
	originalFetch: typeof globalThis.fetch | undefined;
	originalSpawn: ((...args: unknown[]) => unknown) | undefined;
	originalExec: ((...args: unknown[]) => unknown) | undefined;
	originalExecFile: ((...args: unknown[]) => unknown) | undefined;
	originalExecSync: ((...args: unknown[]) => unknown) | undefined;
	originalExecFileSync: ((...args: unknown[]) => unknown) | undefined;
	originalSpawnSync: ((...args: unknown[]) => unknown) | undefined;
	client: SidecarClient;
	sidecarBaseUrl: string;
	active: boolean;
}

let state: GuardState | null = null;

/**
 * Install runtime guards that intercept dangerous APIs and route them
 * through the sidecar. Call this early in your agent's startup, before
 * any tool execution begins.
 *
 * ```typescript
 * import { enableSidecarGuard, SidecarClient } from "@arikernel/sidecar";
 *
 * const client = new SidecarClient({ principalId: "my-agent", authToken: "..." });
 * enableSidecarGuard({ client });
 *
 * // Now fetch() and child_process are mediated by the sidecar
 * ```
 */
export function enableSidecarGuard(options: SidecarGuardOptions): void {
	if (state?.active) {
		throw new Error("Sidecar guard is already enabled. Call disableSidecarGuard() first.");
	}

	const client = options.client;
	// Extract the sidecar base URL so we can exempt sidecar-bound fetch requests
	// from the guard (avoiding infinite recursion).
	const sidecarBaseUrl = extractBaseUrl(client);

	state = {
		originalFetch: undefined,
		originalSpawn: undefined,
		originalExec: undefined,
		originalExecFile: undefined,
		originalExecSync: undefined,
		originalExecFileSync: undefined,
		originalSpawnSync: undefined,
		client,
		sidecarBaseUrl,
		active: true,
	};

	if (options.guardFetch !== false) {
		installFetchGuard(state);
	}
	if (options.guardChildProcess !== false) {
		installChildProcessGuard(state);
	}
}

/**
 * Remove all runtime guards and restore original API behavior.
 */
export function disableSidecarGuard(): void {
	if (!state?.active) return;

	// Restore fetch
	if (state.originalFetch) {
		globalThis.fetch = state.originalFetch;
	}

	// Restore child_process
	restoreChildProcess(state);

	state.active = false;
	state = null;
}

/**
 * Returns true if the sidecar guard is currently active.
 */
export function isSidecarGuardActive(): boolean {
	return state?.active === true;
}

// ── Fetch Guard ──────────────────────────────────────────────────────

function installFetchGuard(s: GuardState): void {
	s.originalFetch = globalThis.fetch;
	const originalFetch = s.originalFetch;

	globalThis.fetch = async function guardedFetch(
		input: string | URL | Request,
		init?: RequestInit,
	): Promise<Response> {
		const url = extractUrl(input);

		// Exempt sidecar-bound requests to avoid infinite recursion —
		// SidecarClient.execute() uses fetch internally.
		if (url.startsWith(s.sidecarBaseUrl)) {
			return originalFetch.call(globalThis, input, init);
		}

		const method = (init?.method ?? "GET").toLowerCase();
		const action = mapHttpMethod(method);

		const params: Record<string, unknown> = { url };
		if (init?.headers) {
			params.headers = normalizeHeaders(
				init.headers as Record<string, string> | Headers | [string, string][],
			);
		}
		if (init?.body !== undefined && init?.body !== null) {
			params.body = typeof init.body === "string" ? init.body : String(init.body);
		}

		const result = await s.client.execute("http", action, params, [
			{
				source: "web" as const,
				origin: safeHostname(url),
				confidence: 1.0,
				addedAt: new Date().toISOString(),
			},
		]);

		if (!result.allowed) {
			throw new SidecarGuardError(
				`Sidecar blocked HTTP ${method.toUpperCase()} ${url}: ${result.error ?? "denied by policy"}`,
			);
		}

		return buildResponse(result.result);
	};
}

// ── Child Process Guard ──────────────────────────────────────────────

function installChildProcessGuard(s: GuardState): void {
	// Use createRequire to access the CJS child_process module, whose
	// exports are mutable. ESM imports that destructured before the guard
	// was installed will retain original references — this is documented
	// as a limitation of cooperative guarding.
	const require = createRequire(import.meta.url);
	const cp = require("node:child_process");

	s.originalSpawn = cp.spawn;
	s.originalExec = cp.exec;
	s.originalExecFile = cp.execFile;
	s.originalExecSync = cp.execSync;
	s.originalExecFileSync = cp.execFileSync;
	s.originalSpawnSync = cp.spawnSync;

	const makeBlocker = (name: string) => {
		return function blockedChildProcess(..._args: unknown[]): never {
			throw new SidecarGuardError(
				`child_process.${name}() is blocked by the sidecar guard. Use sidecarClient.execute("shell", "exec", { executable, args }) to run commands through the sidecar's policy engine.`,
			);
		};
	};

	cp.spawn = makeBlocker("spawn");
	cp.exec = makeBlocker("exec");
	cp.execFile = makeBlocker("execFile");
	cp.execSync = makeBlocker("execSync");
	cp.execFileSync = makeBlocker("execFileSync");
	cp.spawnSync = makeBlocker("spawnSync");
}

function restoreChildProcess(s: GuardState): void {
	const require = createRequire(import.meta.url);
	const cp = require("node:child_process");

	if (s.originalSpawn) cp.spawn = s.originalSpawn;
	if (s.originalExec) cp.exec = s.originalExec;
	if (s.originalExecFile) cp.execFile = s.originalExecFile;
	if (s.originalExecSync) cp.execSync = s.originalExecSync;
	if (s.originalExecFileSync) cp.execFileSync = s.originalExecFileSync;
	if (s.originalSpawnSync) cp.spawnSync = s.originalSpawnSync;
}

// ── Helpers ──────────────────────────────────────────────────────────

function extractUrl(input: string | URL | Request): string {
	if (typeof input === "string") return input;
	if (input instanceof URL) return input.toString();
	return input.url;
}

function safeHostname(url: string): string {
	try {
		return new URL(url).hostname;
	} catch {
		return "unknown";
	}
}

function mapHttpMethod(method: string): string {
	switch (method) {
		case "get":
			return "get";
		case "post":
			return "post";
		case "put":
			return "put";
		case "delete":
			return "delete";
		case "patch":
			return "patch";
		case "head":
			return "head";
		case "options":
			return "options";
		default:
			return method;
	}
}

function normalizeHeaders(headers: Record<string, string> | Headers | [string, string][]): Record<string, string> {
	const result: Record<string, string> = {};
	if (headers instanceof Headers) {
		headers.forEach((value, key) => {
			result[key] = value;
		});
	} else if (Array.isArray(headers)) {
		for (const [key, value] of headers) {
			result[key] = value;
		}
	} else {
		Object.assign(result, headers);
	}
	return result;
}

function buildResponse(data: unknown): Response {
	const body = typeof data === "string" ? data : JSON.stringify(data ?? null);
	return new Response(body, {
		status: 200,
		headers: { "Content-Type": "application/json" },
	});
}

function extractBaseUrl(client: SidecarClient): string {
	return client.endpoint;
}

/**
 * Error thrown when the sidecar guard blocks an operation.
 */
export class SidecarGuardError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "SidecarGuardError";
	}
}
