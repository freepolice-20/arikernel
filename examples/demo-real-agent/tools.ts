/**
 * Tool definitions and execution for the real-agent demo.
 *
 * Each tool routes through Ari Kernel before executing.
 * The whole point: agent -> Ari Kernel -> tool executor.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { ToolCallDeniedError } from "@arikernel/core";
import type { ToolCall, ToolResult } from "@arikernel/core";
import { now } from "@arikernel/core";
import type { createFirewall } from "@arikernel/runtime";

type Firewall = ReturnType<typeof createFirewall>;

const FIXTURES_DIR = resolve(import.meta.dirname ?? ".", "fixtures");

// ── OpenAI function-calling tool definitions ─────────────────────────

export const TOOL_DEFINITIONS = [
	{
		type: "function" as const,
		function: {
			name: "fetch_web_page",
			description: "Fetch and return the text content of a web page given its URL.",
			parameters: {
				type: "object" as const,
				properties: {
					url: { type: "string", description: "The URL of the web page to fetch" },
				},
				required: ["url"],
			},
		},
	},
	{
		type: "function" as const,
		function: {
			name: "read_file",
			description: "Read and return the contents of a local file.",
			parameters: {
				type: "object" as const,
				properties: {
					path: { type: "string", description: "The file path to read" },
				},
				required: ["path"],
			},
		},
	},
	{
		type: "function" as const,
		function: {
			name: "post_http",
			description: "Send data to a URL via HTTP POST.",
			parameters: {
				type: "object" as const,
				properties: {
					url: { type: "string", description: "The destination URL" },
					body: { type: "string", description: "The data to send" },
				},
				required: ["url", "body"],
			},
		},
	},
];

// ── Stub HTTP executor ───────────────────────────────────────────────
// Replaces the real HttpExecutor so the demo doesn't make network calls.
// The pipeline still runs all security checks; only the I/O is stubbed.

export function registerStubExecutors(firewall: Firewall): void {
	firewall.registerExecutor({
		toolClass: "http",
		async execute(toolCall: ToolCall): Promise<ToolResult> {
			return {
				callId: toolCall.id,
				success: true,
				data: { status: 200, body: "(stubbed)" },
				durationMs: 0,
				taintLabels: [
					{
						source: "web" as const,
						origin: String(toolCall.parameters.url ?? ""),
						confidence: 1.0,
						addedAt: now(),
					},
				],
			};
		},
	});
}

// ── Tool result ──────────────────────────────────────────────────────

export interface ToolCallResult {
	success: boolean;
	output: string;
	denied: boolean;
	reason?: string;
	/** True when denied at capability request level (never reached execute). */
	capabilityDenied?: boolean;
	/** Capability class that was denied. */
	capabilityClass?: string;
	/** Tool class for the denied request. */
	toolClass?: string;
	/** Action for the denied request. */
	action?: string;
}

// ── Execute a tool call through Ari Kernel ───────────────────────────

export async function executeTool(
	firewall: Firewall,
	toolName: string,
	args: Record<string, unknown>,
): Promise<ToolCallResult> {
	switch (toolName) {
		case "fetch_web_page":
			return fetchWebPage(firewall, args.url as string);
		case "read_file":
			return readFile(firewall, args.path as string);
		case "post_http":
			return postHttp(firewall, args.url as string, args.body as string);
		default:
			return { success: false, output: `Unknown tool: ${toolName}`, denied: false };
	}
}

// ── fetch_web_page ───────────────────────────────────────────────────
// Routes through Ari Kernel as http.get with web taint.
// Returns local fixture content (simulates the fetched page).

async function fetchWebPage(firewall: Firewall, url: string): Promise<ToolCallResult> {
	const grant = firewall.requestCapability("http.read");
	if (!grant.granted) {
		return {
			success: false,
			output: "",
			denied: true,
			reason: grant.reason ?? "Capability denied",
			capabilityDenied: true,
			capabilityClass: "http.read",
			toolClass: "http",
			action: "get",
		};
	}

	try {
		await firewall.execute({
			toolClass: "http",
			action: "get",
			parameters: { url },
			grantId: grant.grant?.id,
			taintLabels: [
				{ source: "web" as const, origin: url, confidence: 0.9, addedAt: new Date().toISOString() },
			],
		});
	} catch (err) {
		if (err instanceof ToolCallDeniedError) {
			return { success: false, output: "", denied: true, reason: err.decision.reason, toolClass: "http", action: "get" };
		}
	}

	// Return fixture content simulating the web page
	const content = readFileSync(resolve(FIXTURES_DIR, "malicious-page.html"), "utf-8");
	return { success: true, output: content, denied: false };
}

// ── read_file ────────────────────────────────────────────────────────
// Routes through Ari Kernel as file.read.

async function readFile(firewall: Firewall, path: string): Promise<ToolCallResult> {
	const grant = firewall.requestCapability("file.read");
	if (!grant.granted) {
		return {
			success: false,
			output: "",
			denied: true,
			reason: grant.reason ?? "Capability denied",
			capabilityDenied: true,
			capabilityClass: "file.read",
			toolClass: "file",
			action: "read",
		};
	}

	try {
		await firewall.execute({
			toolClass: "file",
			action: "read",
			parameters: { path },
			grantId: grant.grant?.id,
		});
	} catch (err) {
		if (err instanceof ToolCallDeniedError) {
			return { success: false, output: "", denied: true, reason: err.decision.reason, toolClass: "file", action: "read" };
		}
		throw err;
	}

	// If Ari Kernel allowed the read, read the actual file
	try {
		const content = readFileSync(resolve(path), "utf-8");
		return { success: true, output: content, denied: false };
	} catch {
		return { success: false, output: "File not found or unreadable", denied: false };
	}
}

// ── post_http ────────────────────────────────────────────────────────
// Routes through Ari Kernel as http.post. Actual POST is stubbed.

async function postHttp(firewall: Firewall, url: string, body: string): Promise<ToolCallResult> {
	const grant = firewall.requestCapability("http.write");
	if (!grant.granted) {
		return {
			success: false,
			output: "",
			denied: true,
			reason: grant.reason ?? "Capability denied",
			capabilityDenied: true,
			capabilityClass: "http.write",
			toolClass: "http",
			action: "post",
		};
	}

	try {
		await firewall.execute({
			toolClass: "http",
			action: "post",
			parameters: { url, body },
			grantId: grant.grant?.id,
		});
	} catch (err) {
		if (err instanceof ToolCallDeniedError) {
			return { success: false, output: "", denied: true, reason: err.decision.reason, toolClass: "http", action: "post" };
		}
		throw err;
	}

	// If somehow allowed, stub the response (never hits a real server)
	return { success: true, output: "POST completed (stubbed)", denied: false };
}
