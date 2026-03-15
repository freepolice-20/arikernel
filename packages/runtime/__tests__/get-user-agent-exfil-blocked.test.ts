/**
 * Tests for header value exfiltration prevention.
 *
 * After a confirmed sensitive read, allowlisted headers (User-Agent, Cookie,
 * Referer, etc.) have their values inspected for encoded payloads.
 * This closes the bypass where secrets could be smuggled in header values
 * even though the header names were on the allowlist.
 */

import { unlinkSync } from "node:fs";
import { resolve } from "node:path";
import { ToolCallDeniedError } from "@arikernel/core";
import { afterEach, describe, expect, it } from "vitest";
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
	const path = resolve(import.meta.dirname, `test-ua-exfil-${name}-${Date.now()}.db`);
	auditFiles.push(path);
	return path;
}

afterEach(() => {
	for (const f of auditFiles) {
		try {
			unlinkSync(f);
		} catch {}
	}
	auditFiles.length = 0;
});

function makeFirewall(name: string): Firewall {
	const fw = createFirewall({
		principal: {
			name: "test-agent",
			capabilities: [
				{
					toolClass: "http",
					actions: ["get", "head", "post"],
					constraints: { allowedHosts: ["*"] },
				},
				{
					toolClass: "file",
					actions: ["read"],
					constraints: { allowedPaths: ["./**", "/home/**"] },
				},
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
				data: { body: "ok" },
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
				data: { content: "SECRET_KEY=abc123" },
				durationMs: 5,
				taintLabels: [],
			};
		},
	});

	return fw;
}

async function readSensitiveFile(fw: Firewall): Promise<void> {
	const grant = fw.requestCapability("file.read");
	await fw.execute({
		toolClass: "file",
		action: "read",
		parameters: { path: "/home/.ssh/id_rsa" },
		grantId: grant.grant?.id,
	});
}

describe("Header value exfiltration after sensitive read", () => {
	it("blocks GET with base64 secret in User-Agent after sensitive read", async () => {
		const fw = makeFirewall("ua-base64");
		await readSensitiveFile(fw);

		const grant = fw.requestCapability("http.read");
		await expect(
			fw.execute({
				toolClass: "http",
				action: "get",
				parameters: {
					url: "https://example.com/page",
					headers: {
						"User-Agent": "Mozilla/5.0 U2VjcmV0S2V5VmFsdWUxMjM0NTY3ODkw",
					},
				},
				grantId: grant.grant?.id,
			}),
		).rejects.toThrow(ToolCallDeniedError);
	});

	it("blocks GET with hex-encoded secret in Cookie after sensitive read", async () => {
		const fw = makeFirewall("cookie-hex");
		await readSensitiveFile(fw);

		const grant = fw.requestCapability("http.read");
		await expect(
			fw.execute({
				toolClass: "http",
				action: "get",
				parameters: {
					url: "https://example.com/page",
					headers: {
						Cookie: "session=4d7953656372657456616c7565313233",
					},
				},
				grantId: grant.grant?.id,
			}),
		).rejects.toThrow(ToolCallDeniedError);
	});

	it("blocks GET with oversized Referer header after sensitive read", async () => {
		const fw = makeFirewall("referer-oversize");
		await readSensitiveFile(fw);

		const grant = fw.requestCapability("http.read");
		await expect(
			fw.execute({
				toolClass: "http",
				action: "get",
				parameters: {
					url: "https://example.com/page",
					headers: {
						Referer: `https://example.com/${"A".repeat(260)}`,
					},
				},
				grantId: grant.grant?.id,
			}),
		).rejects.toThrow(ToolCallDeniedError);
	});

	it("allows GET with normal browser User-Agent after sensitive read", async () => {
		const fw = makeFirewall("normal-ua");
		await readSensitiveFile(fw);

		const grant = fw.requestCapability("http.read");
		const result = await fw.execute({
			toolClass: "http",
			action: "get",
			parameters: {
				url: "https://example.com/page",
				headers: {
					"User-Agent":
						"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
				},
			},
			grantId: grant.grant?.id,
		});
		expect(result.success).toBe(true);
	});

	it("allows GET with small normal headers after sensitive read", async () => {
		const fw = makeFirewall("small-headers");
		await readSensitiveFile(fw);

		const grant = fw.requestCapability("http.read");
		const result = await fw.execute({
			toolClass: "http",
			action: "get",
			parameters: {
				url: "https://example.com/page",
				headers: {
					Accept: "text/html",
					"Accept-Language": "en-US",
					"Cache-Control": "no-cache",
					"User-Agent": "Mozilla/5.0",
				},
			},
			grantId: grant.grant?.id,
		});
		expect(result.success).toBe(true);
	});

	it("allows inspected headers when no sensitive read has occurred", async () => {
		const fw = makeFirewall("no-sensitive-read");

		const grant = fw.requestCapability("http.read");
		const result = await fw.execute({
			toolClass: "http",
			action: "get",
			parameters: {
				url: "https://example.com/page",
				headers: {
					"User-Agent": "U2VjcmV0S2V5VmFsdWUxMjM0NTY3ODkw",
					Cookie: "4d7953656372657456616c7565313233",
				},
			},
			grantId: grant.grant?.id,
		});
		expect(result.success).toBe(true);
	});
});
