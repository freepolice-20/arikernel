import { PRESETS, getPreset } from "@arikernel/core";
import { afterEach, describe, expect, it } from "vitest";
import { createKernel, resetDefaultKernel } from "../src/kernel.js";

afterEach(() => {
	resetDefaultKernel();
});

describe("createKernel", () => {
	it("creates a kernel with zero-config defaults", () => {
		const kernel = createKernel();
		expect(kernel.preset).toBe("default");
		expect(kernel.autoScope).toBe(false);
	});

	it("creates a kernel with a named preset", () => {
		const kernel = createKernel({ preset: "safe-research" });
		expect(kernel.preset).toBe("safe-research");
	});

	it("creates a kernel with custom allow overrides", () => {
		const kernel = createKernel({
			allow: { httpGet: true, fileRead: ["./mydata/**"] },
		});
		expect(kernel.preset).toBe("custom");
	});

	it("creates a kernel with autoScope enabled", () => {
		const kernel = createKernel({ autoScope: true });
		expect(kernel.autoScope).toBe(true);
	});

	it("throws on unknown preset", () => {
		expect(() => createKernel({ preset: "nonexistent" as any })).toThrow("Unknown preset");
	});
});

describe("kernel.createFirewall", () => {
	it("returns a working Firewall from zero-config", () => {
		const kernel = createKernel();
		const fw = kernel.createFirewall();
		expect(fw.runId).toBeDefined();

		// HTTP GET should be granted
		const grant = fw.requestCapability("http.read");
		expect(grant.granted).toBe(true);

		// Shell should be denied
		const shellGrant = fw.requestCapability("shell.exec");
		expect(shellGrant.granted).toBe(false);

		fw.close();
	});

	it("returns a working Firewall from preset", () => {
		const kernel = createKernel({ preset: "safe-research" });
		const fw = kernel.createFirewall();

		const httpGrant = fw.requestCapability("http.read");
		expect(httpGrant.granted).toBe(true);

		const shellGrant = fw.requestCapability("shell.exec");
		expect(shellGrant.granted).toBe(false);

		const fileWriteGrant = fw.requestCapability("file.write");
		expect(fileWriteGrant.granted).toBe(false);

		fw.close();
	});

	it("workspace-assistant allows file write and has shell capability", () => {
		const kernel = createKernel({ preset: "workspace-assistant" });
		const fw = kernel.createFirewall();

		const writeGrant = fw.requestCapability("file.write");
		expect(writeGrant.granted).toBe(true);

		// Shell capability exists (approval-gated in policy, but capability is present)
		const shellGrant = fw.requestCapability("shell.exec");
		expect(shellGrant.reason).toBeDefined();

		fw.close();
	});

	it("automation-agent allows http.write but denies filesystem", () => {
		const kernel = createKernel({ preset: "automation-agent" });
		const fw = kernel.createFirewall();

		const httpWrite = fw.requestCapability("http.write");
		expect(httpWrite.granted).toBe(true);

		const fileRead = fw.requestCapability("file.read");
		expect(fileRead.granted).toBe(false);

		fw.close();
	});

	it("custom allow overrides work", () => {
		const kernel = createKernel({
			allow: { httpGet: true, httpPost: true, shell: true },
		});
		const fw = kernel.createFirewall();

		expect(fw.requestCapability("http.read").granted).toBe(true);

		// Shell has capability and approval-gated policy
		const shell = fw.requestCapability("shell.exec");
		expect(shell.reason).toBeDefined();

		fw.close();
	});
});

describe("kernel.selectScope", () => {
	it("selects safe-research for web-related tasks", () => {
		const kernel = createKernel({ autoScope: true });
		const result = kernel.selectScope("summarize this webpage");
		expect(result.preset).toBe("safe-research");
		expect(kernel.preset).toBe("safe-research");
	});

	it("selects rag-reader for document analysis tasks", () => {
		const kernel = createKernel({ autoScope: true });
		const result = kernel.selectScope("analyze this PDF document");
		expect(result.preset).toBe("rag-reader");
	});

	it("selects workspace-assistant for coding tasks", () => {
		const kernel = createKernel({ autoScope: true });
		const result = kernel.selectScope("refactor the code in this repo");
		expect(result.preset).toBe("workspace-assistant");
	});

	it("selects automation-agent for workflow tasks", () => {
		const kernel = createKernel({ autoScope: true });
		const result = kernel.selectScope("sync these records to a CRM");
		expect(result.preset).toBe("automation-agent");
	});

	it("falls back to safe-research for ambiguous tasks", () => {
		const kernel = createKernel({ autoScope: true });
		const result = kernel.selectScope("do something");
		expect(result.preset).toBe("safe-research");
		expect(result.confidence).toBe(0);
	});

	it("does not change kernel preset when autoScope is false", () => {
		const kernel = createKernel({ preset: "rag-reader" });
		kernel.selectScope("summarize this webpage");
		expect(kernel.preset).toBe("rag-reader");
	});
});

describe("presets", () => {
	it("all preset IDs are loadable", () => {
		for (const id of Object.keys(PRESETS) as Array<keyof typeof PRESETS>) {
			const preset = getPreset(id);
			expect(preset.id).toBe(id);
			expect(preset.capabilities.length).toBeGreaterThan(0);
			expect(preset.policies.length).toBeGreaterThan(0);
		}
	});

	it("safe-research denies shell and file write", () => {
		const preset = getPreset("safe-research");
		const denyIds = preset.policies.filter((p) => p.decision === "deny").map((p) => p.id);
		expect(denyIds).toContain("deny-shell");
		expect(denyIds).toContain("deny-file-write");
	});

	it("rag-reader has database query capability", () => {
		const preset = getPreset("rag-reader");
		const dbCap = preset.capabilities.find((c) => c.toolClass === "database");
		expect(dbCap).toBeDefined();
		expect(dbCap?.actions).toContain("query");
	});
});
