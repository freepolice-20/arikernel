import { describe, expect, it, afterEach } from "vitest";
import { Firewall, createKernel } from "../src/index.js";

const ALLOW_ALL = {
	id: "allow-all",
	name: "Allow all",
	priority: 100,
	match: {} as const,
	decision: "allow" as const,
};

const BASE = {
	principal: { name: "test-agent", capabilities: [] },
	policies: [ALLOW_ALL],
	auditLog: ":memory:" as const,
};

// ── enforcement mode production guard ─────────────────────────────────────────

describe("Enforcement mode production guard", () => {
	let fw: Firewall | undefined;

	afterEach(() => {
		try {
			fw?.close();
		} catch {}
		fw = undefined;
	});

	it("throws when NODE_ENV=production and mode is omitted", () => {
		const prev = process.env.NODE_ENV;
		process.env.NODE_ENV = "production";
		try {
			expect(() => new Firewall(BASE)).toThrow(
				"AriKernel: enforcement mode must be explicit in production",
			);
		} finally {
			process.env.NODE_ENV = prev;
		}
	});

	it("allows explicit embedded mode in production (with warning)", () => {
		const prev = process.env.NODE_ENV;
		process.env.NODE_ENV = "production";
		try {
			expect(
				() =>
					(fw = new Firewall({ ...BASE, mode: "embedded" })),
			).not.toThrow();
		} finally {
			process.env.NODE_ENV = prev;
		}
	});

	it("throws sidecar config error when mode=sidecar and no sidecar options", () => {
		expect(() => new Firewall({ ...BASE, mode: "sidecar" })).toThrow(
			'Firewall mode is "sidecar" but no sidecar connection options were provided',
		);
	});

	it("allows sidecar mode when sidecar options are provided", () => {
		expect(
			() =>
				(fw = new Firewall({
					...BASE,
					mode: "sidecar",
					sidecar: { baseUrl: "http://localhost:8787" },
				})),
		).not.toThrow();
	});

	it("allows omitted mode in non-production (defaults to embedded with warning)", () => {
		const prev = process.env.NODE_ENV;
		process.env.NODE_ENV = "development";
		try {
			expect(() => (fw = new Firewall(BASE))).not.toThrow();
		} finally {
			process.env.NODE_ENV = prev;
		}
	});

	it("createKernel throws when NODE_ENV=production and mode is omitted", () => {
		const prev = process.env.NODE_ENV;
		process.env.NODE_ENV = "production";
		try {
			const kernel = createKernel({ preset: "safe" });
			expect(() => kernel.createFirewall()).toThrow(
				"AriKernel: enforcement mode must be explicit in production",
			);
		} finally {
			process.env.NODE_ENV = prev;
		}
	});
});
