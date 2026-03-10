import { describe, expect, it } from "vitest";
import { canonicalizePath, isPathAllowed } from "../src/path-security.js";

describe("canonicalizePath", () => {
	it("resolves relative paths", () => {
		const result = canonicalizePath("./data/file.txt", "/project");
		expect(result).toContain("data");
		expect(result).not.toContain("./");
	});

	it("collapses ../ traversal", () => {
		const result = canonicalizePath("./data/../../../etc/passwd", "/project");
		expect(result).not.toContain("..");
		expect(result).toContain("etc");
	});

	it("normalizes multiple slashes", () => {
		const result = canonicalizePath("./data///file.txt", "/project");
		expect(result).not.toContain("///");
	});
});

describe("isPathAllowed", () => {
	it("allows paths within a glob pattern", () => {
		const { allowed } = isPathAllowed("./data/report.csv", ["./data/**"], "/project");
		expect(allowed).toBe(true);
	});

	it("blocks traversal escaping the allowed directory", () => {
		const { allowed } = isPathAllowed("./data/../../etc/passwd", ["./data/**"], "/project");
		expect(allowed).toBe(false);
	});

	it("blocks absolute paths outside the allowed jail", () => {
		const { allowed } = isPathAllowed("/etc/shadow", ["./data/**"], "/project");
		expect(allowed).toBe(false);
	});

	it("allows exact path matches", () => {
		const { allowed } = isPathAllowed("./config.json", ["./config.json"], "/project");
		expect(allowed).toBe(true);
	});

	it("blocks paths that share a prefix but are not subdirectories", () => {
		const { allowed } = isPathAllowed("./data-secret/key", ["./data/**"], "/project");
		expect(allowed).toBe(false);
	});
});
