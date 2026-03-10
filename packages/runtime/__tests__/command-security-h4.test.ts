import { describe, expect, it } from "vitest";
import { validateCommand } from "../src/command-security.js";

describe("H4: command binary path validation", () => {
	const allowed = ["git", "ls", "cat", "node"];

	it("allows bare binary names in allowlist", () => {
		expect(validateCommand("git status", allowed)).toBeNull();
		expect(validateCommand("ls -la", allowed)).toBeNull();
	});

	it("allows trusted path prefixes", () => {
		expect(validateCommand("/usr/bin/git status", allowed)).toBeNull();
		expect(validateCommand("/usr/local/bin/node index.js", allowed)).toBeNull();
		expect(validateCommand("/bin/cat file.txt", allowed)).toBeNull();
	});

	it("blocks untrusted path prefixes", () => {
		const result = validateCommand("/tmp/evil/git status", allowed);
		expect(result).not.toBeNull();
		expect(result).toContain("not in a trusted location");
	});

	it("blocks relative path attacks", () => {
		const result = validateCommand("./malicious/git status", allowed);
		expect(result).not.toBeNull();
		expect(result).toContain("not in a trusted location");
	});

	it("blocks home directory path attacks", () => {
		const result = validateCommand("/home/attacker/.local/bin/git push", allowed);
		expect(result).not.toBeNull();
		expect(result).toContain("not in a trusted location");
	});

	it("still rejects binaries not in allowlist even with trusted path", () => {
		const result = validateCommand("/usr/bin/curl http://evil.com", allowed);
		expect(result).not.toBeNull();
		expect(result).toContain("not in allowed commands");
	});

	it("still rejects shell metacharacters", () => {
		const result = validateCommand("git status; rm -rf /", allowed);
		expect(result).not.toBeNull();
		expect(result).toContain("dangerous shell metacharacter");
	});
});
