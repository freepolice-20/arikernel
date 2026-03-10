import { resolve } from "node:path";
import { ToolCallDeniedError, now } from "@arikernel/core";
import type { TaintLabel } from "@arikernel/core";
import { type Firewall, createFirewall } from "@arikernel/runtime";
import { afterEach, describe, expect, it } from "vitest";
import { LlamaIndexAdapter } from "../src/llamaindex.js";

const POLICY_PATH = resolve(
	import.meta.dirname,
	"..",
	"..",
	"..",
	"policies",
	"safe-defaults.yaml",
);

function makeFirewall(name: string, opts?: { threshold?: number }): Firewall {
	return createFirewall({
		principal: {
			name,
			capabilities: [
				{ toolClass: "http", actions: ["get"], constraints: { allowedHosts: ["example.com"] } },
				{ toolClass: "file", actions: ["read"], constraints: { allowedPaths: ["./data/**"] } },
			],
		},
		policies: POLICY_PATH,
		auditLog: ":memory:",
		runStatePolicy: opts?.threshold ? { maxDeniedSensitiveActions: opts.threshold } : undefined,
	});
}

describe("LlamaIndexAdapter", () => {
	let fw: Firewall;
	afterEach(() => {
		fw?.close();
	});

	it("creates protected tool functions", async () => {
		fw = makeFirewall("llama-basic");
		fw.registerExecutor({
			toolClass: "http",
			async execute(tc) {
				return { callId: tc.id, success: true, data: "ok", durationMs: 0, taintLabels: [] };
			},
		});

		const adapter = new LlamaIndexAdapter(fw);
		const httpGet = adapter.tool("http", "get");

		const result = await httpGet({ url: "https://example.com/api" });
		expect(result.success).toBe(true);
	});

	it("denies tool call on constraint violation", async () => {
		fw = makeFirewall("llama-deny");
		fw.registerExecutor({
			toolClass: "file",
			async execute(tc) {
				return { callId: tc.id, success: true, data: null, durationMs: 0, taintLabels: [] };
			},
		});

		const adapter = new LlamaIndexAdapter(fw);
		const fileRead = adapter.tool("file", "read");

		await expect(fileRead({ path: "~/.ssh/id_rsa" })).rejects.toThrow(ToolCallDeniedError);
	});

	it("supports dynamic taint derivation via taintFrom", async () => {
		fw = makeFirewall("llama-taint");
		fw.registerExecutor({
			toolClass: "http",
			async execute(tc) {
				return { callId: tc.id, success: true, data: null, durationMs: 0, taintLabels: [] };
			},
		});

		const adapter = new LlamaIndexAdapter(fw);
		const httpGet = adapter.tool("http", "get", {
			taintFrom: (params) => {
				const url = String(params.url ?? "");
				if (url.includes("external")) {
					return [{ source: "web" as const, origin: url, confidence: 0.9, addedAt: now() }];
				}
				return [];
			},
		});

		// Should succeed — taint is added but doesn't block HTTP GET
		const result = await httpGet({ url: "https://example.com/external" });
		expect(result.success).toBe(true);
	});

	it("protects multiple tools at once via protectTools", async () => {
		fw = makeFirewall("llama-multi");
		for (const tc of ["http", "file"]) {
			fw.registerExecutor({
				toolClass: tc,
				async execute(toolCall) {
					return { callId: toolCall.id, success: true, data: tc, durationMs: 0, taintLabels: [] };
				},
			});
		}

		const adapter = new LlamaIndexAdapter(fw);
		const tools = adapter.protectTools({
			fetch_url: { toolClass: "http", action: "get" },
			read_file: { toolClass: "file", action: "read" },
		});

		expect(Object.keys(tools)).toEqual(["fetch_url", "read_file"]);

		const httpResult = await tools.fetch_url({ url: "https://example.com" });
		expect(httpResult.data).toBe("http");
	});

	it("triggers quarantine after repeated denials", async () => {
		fw = makeFirewall("llama-quarantine", { threshold: 2 });
		fw.registerExecutor({
			toolClass: "file",
			async execute(tc) {
				return { callId: tc.id, success: true, data: null, durationMs: 0, taintLabels: [] };
			},
		});

		const adapter = new LlamaIndexAdapter(fw);
		const fileRead = adapter.tool("file", "read");

		for (const path of ["~/.ssh/id_rsa", "~/.aws/credentials", "/etc/shadow"]) {
			try {
				await fileRead({ path });
			} catch {}
		}

		expect(fw.isRestricted).toBe(true);
	});
});
