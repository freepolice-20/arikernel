import { unlinkSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
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
	const path = resolve(import.meta.dirname, `test-autotaint-${name}-${Date.now()}.db`);
	auditFiles.push(path);
	return path;
}

afterEach(() => {
	vi.restoreAllMocks();
	for (const f of auditFiles) {
		try {
			unlinkSync(f);
		} catch {}
	}
	auditFiles.length = 0;
});

function makeFirewall(name: string): Firewall {
	return createFirewall({
		principal: {
			name: "test-agent",
			capabilities: [
				{ toolClass: "http", actions: ["get"] },
				{ toolClass: "retrieval", actions: ["search"] },
				{
					toolClass: "database",
					actions: ["query"],
					constraints: { allowedDatabases: ["analytics"] },
				},
			],
		},
		policies: POLICY_PATH,
		auditLog: auditPath(name),
	});
}

describe("Auto-taint: HTTP executor", () => {
	it("result carries web:<hostname> taint after HTTP GET", async () => {
		vi.stubGlobal("fetch", async () => ({
			ok: true,
			status: 200,
			headers: { get: () => "text/plain", entries: () => [] },
			text: async () => "some web content",
		}));

		const fw = makeFirewall("http");
		try {
			const grant = fw.requestCapability("http.read");
			expect(grant.granted).toBe(true);

			const result = await fw.execute({
				toolClass: "http",
				action: "get",
				parameters: { url: "https://example.com/page" },
				grantId: grant.grant?.id,
			});

			const webTaints = result.taintLabels.filter((t) => t.source === "web");
			expect(webTaints).toHaveLength(1);
			expect(webTaints[0].origin).toBe("example.com");
		} finally {
			fw.close();
		}
	});

	it("taint label is recorded in the audit log", async () => {
		vi.stubGlobal("fetch", async () => ({
			ok: true,
			status: 200,
			headers: { get: () => "text/plain", entries: () => [] },
			text: async () => "content",
		}));

		const fw = makeFirewall("http-audit");
		try {
			const grant = fw.requestCapability("http.read");
			await fw.execute({
				toolClass: "http",
				action: "get",
				parameters: { url: "https://news.example.com/article" },
				grantId: grant.grant?.id,
			});

			const events = fw.getEvents();
			const httpEvent = events.find((e) => e.toolCall.toolClass === "http");
			expect(httpEvent).toBeDefined();
			// The result taint labels are on the result, which is stored in the audit event
			expect(httpEvent?.result).toBeDefined();
			const resultTaints = (httpEvent?.result as any)?.taintLabels ?? [];
			const webTaint = resultTaints.find((t: any) => t.source === "web");
			expect(webTaint).toBeDefined();
			expect(webTaint.origin).toBe("news.example.com");
		} finally {
			fw.close();
		}
	});
});

describe("Auto-taint: Retrieval executor", () => {
	it("result carries rag:<source> taint after retrieval search", async () => {
		const fw = makeFirewall("rag");
		try {
			const result = await fw.execute({
				toolClass: "retrieval",
				action: "search",
				parameters: { source: "customer_docs", query: "refund policy" },
			});

			const ragTaints = result.taintLabels.filter((t) => t.source === "rag");
			expect(ragTaints).toHaveLength(1);
			expect(ragTaints[0].origin).toBe("customer_docs");
		} finally {
			fw.close();
		}
	});
});

describe("Auto-taint: pipeline taint merge", () => {
	it("merges executor auto-taints with propagated input taints", async () => {
		vi.stubGlobal("fetch", async () => ({
			ok: true,
			status: 200,
			headers: { get: () => "text/plain", entries: () => [] },
			text: async () => "data",
		}));

		const fw = makeFirewall("merge");
		try {
			const grant = fw.requestCapability("http.read");
			const result = await fw.execute({
				toolClass: "http",
				action: "get",
				parameters: { url: "https://api.example.com/data" },
				grantId: grant.grant?.id,
				// Simulate: this call itself is tainted (e.g. URL came from user input)
				taintLabels: [
					{
						source: "user-provided",
						origin: "agent-input",
						confidence: 0.8,
						addedAt: new Date().toISOString(),
					},
				],
			});

			const sources = result.taintLabels.map((t) => t.source);
			// Auto-taint from executor
			expect(sources).toContain("web");
			// Propagated from input taint
			expect(sources).toContain("tool-output");
		} finally {
			fw.close();
		}
	});
});

describe("Auto-taint blocks sensitive capability issuance", () => {
	it("denies database.read capability when context has web taint", () => {
		const fw = makeFirewall("block-sensitive");
		try {
			const webTaint = [
				{
					source: "web" as const,
					origin: "attacker.com",
					confidence: 1.0,
					addedAt: new Date().toISOString(),
				},
			];

			const decision = fw.requestCapability("database.read", { taintLabels: webTaint });
			expect(decision.granted).toBe(false);
			expect(decision.reason).toContain("untrusted taint");
		} finally {
			fw.close();
		}
	});

	it("denies database.read capability when context has rag taint", () => {
		const fw = makeFirewall("block-rag");
		try {
			const ragTaint = [
				{
					source: "rag" as const,
					origin: "external_docs",
					confidence: 1.0,
					addedAt: new Date().toISOString(),
				},
			];

			const decision = fw.requestCapability("database.read", { taintLabels: ragTaint });
			expect(decision.granted).toBe(false);
			expect(decision.reason).toContain("untrusted taint");
		} finally {
			fw.close();
		}
	});
});
