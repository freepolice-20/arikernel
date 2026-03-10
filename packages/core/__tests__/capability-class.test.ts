import { describe, expect, it } from "vitest";
import { CAPABILITY_CLASS_MAP, deriveCapabilityClass } from "../src/types/capability.js";

describe("deriveCapabilityClass", () => {
	it("classifies HTTP HEAD as http.read", () => {
		expect(deriveCapabilityClass("http", "head")).toBe("http.read");
	});

	it("classifies HTTP OPTIONS as http.read", () => {
		expect(deriveCapabilityClass("http", "options")).toBe("http.read");
	});

	it("classifies HTTP GET as http.read", () => {
		expect(deriveCapabilityClass("http", "get")).toBe("http.read");
	});

	it("classifies HTTP POST as http.write", () => {
		expect(deriveCapabilityClass("http", "post")).toBe("http.write");
	});

	it("classifies HTTP PUT as http.write", () => {
		expect(deriveCapabilityClass("http", "put")).toBe("http.write");
	});

	it("classifies HTTP DELETE as http.write", () => {
		expect(deriveCapabilityClass("http", "delete")).toBe("http.write");
	});

	it("normalizes uppercase actions — GET", () => {
		expect(deriveCapabilityClass("http", "GET")).toBe("http.read");
	});

	it("normalizes uppercase actions — HEAD", () => {
		expect(deriveCapabilityClass("http", "HEAD")).toBe("http.read");
	});

	it("normalizes uppercase actions — OPTIONS", () => {
		expect(deriveCapabilityClass("http", "OPTIONS")).toBe("http.read");
	});

	it("normalizes mixed-case actions", () => {
		expect(deriveCapabilityClass("http", "Post")).toBe("http.write");
	});

	it("classifies shell exec", () => {
		expect(deriveCapabilityClass("shell", "exec")).toBe("shell.exec");
	});

	it("classifies database read", () => {
		expect(deriveCapabilityClass("database", "query")).toBe("database.read");
	});

	it("classifies database write", () => {
		expect(deriveCapabilityClass("database", "exec")).toBe("database.write");
		expect(deriveCapabilityClass("database", "mutate")).toBe("database.write");
	});

	it("classifies file read/write", () => {
		expect(deriveCapabilityClass("file", "read")).toBe("file.read");
		expect(deriveCapabilityClass("file", "write")).toBe("file.write");
	});

	it("falls back to write for unknown actions (fail-closed)", () => {
		expect(deriveCapabilityClass("http", "unknown")).toBe("http.write");
	});

	it("covers every action in CAPABILITY_CLASS_MAP", () => {
		for (const [capClass, mapping] of Object.entries(CAPABILITY_CLASS_MAP)) {
			for (const action of mapping.actions) {
				expect(deriveCapabilityClass(mapping.toolClass, action)).toBe(capClass);
			}
		}
	});
});
