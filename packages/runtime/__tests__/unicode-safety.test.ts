import { describe, expect, it } from "vitest";
import { validateCommand } from "../src/command-security.js";
import { RunStateTracker } from "../src/run-state.js";
import { containsDangerousUnicode, normalizeInput } from "../src/unicode-safety.js";

describe("Unicode normalization (NFKC)", () => {
	it("normalizes fullwidth dollar sign to ASCII", () => {
		expect(normalizeInput("\uFF04")).toBe("$");
	});

	it("normalizes fullwidth semicolon to ASCII", () => {
		expect(normalizeInput("\uFF1B")).toBe(";");
	});

	it("normalizes fullwidth solidus to ASCII", () => {
		expect(normalizeInput("\uFF0F")).toBe("/");
	});

	it("normalizes fullwidth parentheses to ASCII", () => {
		expect(normalizeInput("\uFF08\uFF09")).toBe("()");
	});

	it("strips zero-width space", () => {
		expect(normalizeInput("git\u200Bstatus")).toBe("gitstatus");
	});

	it("strips bidi overrides", () => {
		expect(normalizeInput("test\u202Eevil")).toBe("testevil");
	});

	it("strips soft hyphens", () => {
		expect(normalizeInput("pass\u00ADword")).toBe("password");
	});
});

describe("containsDangerousUnicode", () => {
	it("detects zero-width space", () => {
		expect(containsDangerousUnicode("git\u200Bstatus")).toBe(true);
	});

	it("detects bidi override", () => {
		expect(containsDangerousUnicode("test\u202E")).toBe(true);
	});

	it("passes clean ASCII", () => {
		expect(containsDangerousUnicode("git status --all")).toBe(false);
	});
});

describe("command-security: unicode bypass prevention", () => {
	const allowed = ["git", "ls"];

	it("blocks fullwidth semicolon injection", () => {
		// ；(U+FF1B) normalizes to ; which is a metacharacter
		const result = validateCommand("git status\uFF1Brm -rf /", allowed);
		expect(result).not.toBeNull();
		expect(result).toContain("metacharacter");
	});

	it("blocks fullwidth dollar sign injection", () => {
		// ＄(U+FF04) normalizes to $
		const result = validateCommand("git \uFF04(evil)", allowed);
		expect(result).not.toBeNull();
	});

	it("blocks zero-width space in command", () => {
		const result = validateCommand("git\u200B status", allowed);
		expect(result).not.toBeNull();
		expect(result).toContain("invisible Unicode");
	});

	it("blocks bidi override in command", () => {
		const result = validateCommand("git status\u202E", allowed);
		expect(result).not.toBeNull();
		expect(result).toContain("invisible Unicode");
	});

	it("allows clean ASCII commands", () => {
		expect(validateCommand("git status", allowed)).toBeNull();
		expect(validateCommand("ls -la", allowed)).toBeNull();
	});
});

describe("run-state: sensitive path unicode bypass prevention", () => {
	it("detects Cyrillic homoglyph in .ssh path via NFKC", () => {
		const state = new RunStateTracker();
		// Note: Cyrillic ѕ (U+0455) does NOT normalize to ASCII 's' under NFKC.
		// However, fullwidth variants DO normalize. Test the fullwidth case:
		// ．ｓｓｈ (fullwidth) → .ssh
		const fullwidthSsh = "/home/user/\uFF0E\uFF53\uFF53\uFF48/id_rsa";
		expect(state.isSensitivePath(fullwidthSsh)).toBe(true);
	});

	it("detects fullwidth .env path", () => {
		const state = new RunStateTracker();
		// ．ｅｎｖ (fullwidth) → .env
		const fullwidthEnv = "/app/\uFF0E\uFF45\uFF4E\uFF56";
		expect(state.isSensitivePath(fullwidthEnv)).toBe(true);
	});

	it("still detects normal ASCII sensitive paths", () => {
		const state = new RunStateTracker();
		expect(state.isSensitivePath("/home/user/.ssh/id_rsa")).toBe(true);
		expect(state.isSensitivePath("/app/.env")).toBe(true);
		expect(state.isSensitivePath("/home/.aws/credentials")).toBe(true);
	});
});
