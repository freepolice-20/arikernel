import { describe, expect, it } from "vitest";
import { validateCommand, parseCommandString } from "../src/shell.js";

describe("shell executor: unicode bypass prevention", () => {
	it("blocks fullwidth semicolon in arguments", () => {
		// ；(U+FF1B) normalizes to ; which is a metacharacter
		expect(() => validateCommand("git", ["\uFF1Brm"])).toThrow("shell metacharacters");
	});

	it("blocks fullwidth dollar sign in executable", () => {
		expect(() => validateCommand("\uFF04(evil)", [])).toThrow("shell metacharacters");
	});

	it("blocks zero-width space in executable", () => {
		expect(() => validateCommand("git\u200B", [])).toThrow("invisible Unicode");
	});

	it("blocks bidi override in arguments", () => {
		expect(() => validateCommand("git", ["status\u202E"])).toThrow("invisible Unicode");
	});

	it("allows clean ASCII executables and args", () => {
		expect(() => validateCommand("git", ["status"])).not.toThrow();
		expect(() => validateCommand("ls", ["-la"])).not.toThrow();
	});
});

describe("parseCommandString: unicode bypass prevention", () => {
	it("blocks fullwidth semicolon in command string", () => {
		expect(() => parseCommandString("git status\uFF1Brm -rf")).toThrow("shell metacharacters");
	});

	it("blocks zero-width space in command string", () => {
		expect(() => parseCommandString("git\u200B status")).toThrow("invisible Unicode");
	});

	it("allows clean ASCII command strings", () => {
		const result = parseCommandString("git status");
		expect(result.executable).toBe("git");
		expect(result.args).toEqual(["status"]);
	});
});
