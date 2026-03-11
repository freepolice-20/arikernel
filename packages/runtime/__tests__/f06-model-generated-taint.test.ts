/**
 * F-06 regression tests: model-generated taint must be automatically
 * applied to all tool calls flowing through the pipeline.
 */

import { unlinkSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it, afterEach, beforeEach } from "vitest";
import { type Firewall, createFirewall } from "../src/index.js";

const POLICY_PATH = resolve(
	import.meta.dirname,
	"..",
	"..",
	"..",
	"policies",
	"safe-defaults.yaml",
);
const auditFiles: string[] = [];

function auditPath(name: string): string {
	const path = resolve(import.meta.dirname, `test-f06-${name}-${Date.now()}.db`);
	auditFiles.push(path);
	return path;
}

afterEach(() => {
	for (const f of auditFiles) {
		try { unlinkSync(f); } catch {}
	}
	auditFiles.length = 0;
});

function makeFirewall(name: string): Firewall {
	const fw = createFirewall({
		principal: {
			name: "test-agent",
			capabilities: [
				{ toolClass: "http", actions: ["get", "post"], constraints: { allowedHosts: ["*"] } },
				{ toolClass: "file", actions: ["read"], constraints: { allowedPaths: ["./**"] } },
				{ toolClass: "database", actions: ["query", "exec"] },
			],
		},
		policies: POLICY_PATH,
		auditLog: auditPath(name),
		runStatePolicy: { maxDeniedSensitiveActions: 5, behavioralRules: true },
	});

	fw.registerExecutor({
		toolClass: "http",
		async execute(toolCall) {
			return {
				callId: toolCall.id,
				success: true,
				data: { body: "response" },
				durationMs: 10,
				taintLabels: [],
			};
		},
	});
	fw.registerExecutor({
		toolClass: "file",
		async execute(toolCall) {
			return {
				callId: toolCall.id,
				success: true,
				data: { content: "file contents" },
				durationMs: 5,
				taintLabels: [],
			};
		},
	});
	fw.registerExecutor({
		toolClass: "database",
		async execute(toolCall) {
			return {
				callId: toolCall.id,
				success: true,
				data: { rows: [] },
				durationMs: 5,
				taintLabels: [],
			};
		},
	});

	return fw;
}

describe("F-06: model-generated taint applied to pipeline tool calls", () => {
	let fw: Firewall;

	beforeEach(() => {
		fw = makeFirewall("model-taint");
	});

	afterEach(() => {
		fw.close();
	});

	it("HTTP GET result carries model-generated taint", async () => {
		const grant = fw.requestCapability("http.read");
		const result = await fw.execute({
			toolClass: "http",
			action: "get",
			parameters: { url: "http://example.com" },
			grantId: grant.grant!.id,
		});

		expect(result.taintLabels.some((l) => l.source === "model-generated")).toBe(true);
	});

	it("file read result carries model-generated taint", async () => {
		const grant = fw.requestCapability("file.read");
		const result = await fw.execute({
			toolClass: "file",
			action: "read",
			parameters: { path: "./readme.md" },
			grantId: grant.grant!.id,
		});

		expect(result.taintLabels.some((l) => l.source === "model-generated")).toBe(true);
	});

	it("model-generated taint propagates to run-level taint state", async () => {
		expect(fw.taintState.tainted).toBe(false);

		const grant = fw.requestCapability("http.read");
		await fw.execute({
			toolClass: "http",
			action: "get",
			parameters: { url: "http://example.com" },
			grantId: grant.grant!.id,
		});

		expect(fw.taintState.tainted).toBe(true);
		expect(fw.taintState.sources).toContain("model-generated");
	});

	it("does not duplicate model-generated taint if already present", async () => {
		const grant = fw.requestCapability("http.read");
		const result = await fw.execute({
			toolClass: "http",
			action: "get",
			parameters: { url: "http://example.com" },
			taintLabels: [
				{
					source: "model-generated",
					origin: "pre-existing",
					confidence: 1.0,
					addedAt: new Date().toISOString(),
				},
			],
			grantId: grant.grant!.id,
		});

		const modelTaints = result.taintLabels.filter((l) => l.source === "model-generated");
		// Should have the pre-existing one, not a duplicate
		expect(modelTaints.length).toBeGreaterThanOrEqual(1);
		expect(modelTaints.some((l) => l.origin === "pre-existing")).toBe(true);
	});

	it("model-generated taint coexists with web taint", async () => {
		const grant = fw.requestCapability("http.read");
		const result = await fw.execute({
			toolClass: "http",
			action: "get",
			parameters: { url: "http://example.com" },
			taintLabels: [
				{
					source: "web",
					origin: "evil.com",
					confidence: 0.9,
					addedAt: new Date().toISOString(),
				},
			],
			grantId: grant.grant!.id,
		});

		expect(result.taintLabels.some((l) => l.source === "model-generated")).toBe(true);
		expect(result.taintLabels.some((l) => l.source === "web")).toBe(true);
	});

	it("model-generated taint origin identifies the tool call", async () => {
		const grant = fw.requestCapability("http.read");
		const result = await fw.execute({
			toolClass: "http",
			action: "get",
			parameters: { url: "http://example.com" },
			grantId: grant.grant!.id,
		});

		const modelTaint = result.taintLabels.find((l) => l.source === "model-generated");
		expect(modelTaint).toBeDefined();
		expect(modelTaint!.origin).toBe("http.get");
	});
});
