import { describe, expect, it } from "vitest";
import { SidecarServer } from "../src/index.js";

const MINIMAL_POLICY = [
	{
		id: "allow-http",
		name: "Allow HTTP",
		priority: 10,
		match: { toolClass: "http" as const },
		decision: "allow" as const,
	},
];

describe("dev mode loopback restriction", () => {
	it("allows dev mode on 127.0.0.1 (default)", () => {
		expect(
			() => new SidecarServer({ policy: MINIMAL_POLICY }),
		).not.toThrow();
	});

	it("allows dev mode on localhost", () => {
		expect(
			() => new SidecarServer({ policy: MINIMAL_POLICY, host: "localhost" }),
		).not.toThrow();
	});

	it("allows dev mode on ::1", () => {
		expect(
			() => new SidecarServer({ policy: MINIMAL_POLICY, host: "::1" }),
		).not.toThrow();
	});

	it("rejects dev mode on 0.0.0.0", () => {
		expect(
			() => new SidecarServer({ policy: MINIMAL_POLICY, host: "0.0.0.0" }),
		).toThrow("dev mode cannot bind");
	});

	it("rejects dev mode on a real IP", () => {
		expect(
			() => new SidecarServer({ policy: MINIMAL_POLICY, host: "192.168.1.100" }),
		).toThrow("dev mode cannot bind");
	});

	it("allows non-loopback when principals are configured", () => {
		expect(
			() =>
				new SidecarServer({
					policy: MINIMAL_POLICY,
					host: "0.0.0.0",
					principals: { "test-key": { principalId: "alice" } },
				}),
		).not.toThrow();
	});
});
