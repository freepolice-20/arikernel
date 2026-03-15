import { describe, expect, it } from "vitest";
import {
	ACTION_CATEGORIES,
	DATABASE_ACTIONS,
	FILE_ACTIONS,
	HTTP_ACTIONS,
	SHELL_ACTIONS,
	TOOL_CLASS_ACTIONS,
	categorizeAction,
	isKnownAction,
	isWriteAction,
} from "../src/types/actions.js";

describe("TOOL_CLASS_ACTIONS registry", () => {
	it("covers all non-dynamic tool classes", () => {
		expect(TOOL_CLASS_ACTIONS).toHaveProperty("http");
		expect(TOOL_CLASS_ACTIONS).toHaveProperty("file");
		expect(TOOL_CLASS_ACTIONS).toHaveProperty("shell");
		expect(TOOL_CLASS_ACTIONS).toHaveProperty("database");
		expect(TOOL_CLASS_ACTIONS).toHaveProperty("browser");
		expect(TOOL_CLASS_ACTIONS).toHaveProperty("retrieval");
	});

	it("does not list mcp (dynamic actions)", () => {
		expect(TOOL_CLASS_ACTIONS).not.toHaveProperty("mcp");
	});

	it("exports typed action arrays", () => {
		expect(HTTP_ACTIONS).toContain("get");
		expect(HTTP_ACTIONS).toContain("post");
		expect(FILE_ACTIONS).toContain("read");
		expect(FILE_ACTIONS).toContain("write");
		expect(SHELL_ACTIONS).toContain("exec");
		expect(DATABASE_ACTIONS).toContain("query");
		expect(DATABASE_ACTIONS).toContain("mutate");
	});
});

describe("categorizeAction", () => {
	it("classifies HTTP GET/HEAD/OPTIONS as read", () => {
		expect(categorizeAction("http", "get")).toBe("read");
		expect(categorizeAction("http", "head")).toBe("read");
		expect(categorizeAction("http", "options")).toBe("read");
	});

	it("classifies HTTP POST/PUT/PATCH/DELETE as write", () => {
		expect(categorizeAction("http", "post")).toBe("write");
		expect(categorizeAction("http", "put")).toBe("write");
		expect(categorizeAction("http", "patch")).toBe("write");
		expect(categorizeAction("http", "delete")).toBe("write");
	});

	it("classifies file read vs write", () => {
		expect(categorizeAction("file", "read")).toBe("read");
		expect(categorizeAction("file", "write")).toBe("write");
	});

	it("classifies shell exec as execute", () => {
		expect(categorizeAction("shell", "exec")).toBe("execute");
	});

	it("classifies database query as read, exec as execute, mutate as write", () => {
		expect(categorizeAction("database", "query")).toBe("read");
		expect(categorizeAction("database", "exec")).toBe("execute");
		expect(categorizeAction("database", "mutate")).toBe("write");
	});

	it("normalizes action case", () => {
		expect(categorizeAction("http", "GET")).toBe("read");
		expect(categorizeAction("http", "Post")).toBe("write");
		expect(categorizeAction("shell", "EXEC")).toBe("execute");
	});

	it("falls back to write for unknown actions (fail-closed)", () => {
		expect(categorizeAction("http", "unknown")).toBe("write");
		expect(categorizeAction("database", "bulkInsert")).toBe("write");
		expect(categorizeAction("file", "append")).toBe("write");
		expect(categorizeAction("unknown", "anything")).toBe("write");
	});

	it("covers every declared ACTION_CATEGORIES value", () => {
		const seen = new Set<string>();
		for (const [toolClass, actions] of Object.entries(TOOL_CLASS_ACTIONS)) {
			for (const action of actions) {
				seen.add(categorizeAction(toolClass, action));
			}
		}
		for (const cat of ACTION_CATEGORIES) {
			expect(seen.has(cat)).toBe(true);
		}
	});
});

describe("isKnownAction", () => {
	it("returns true for registered actions", () => {
		expect(isKnownAction("http", "get")).toBe(true);
		expect(isKnownAction("shell", "exec")).toBe(true);
		expect(isKnownAction("database", "mutate")).toBe(true);
	});

	it("normalizes case", () => {
		expect(isKnownAction("http", "GET")).toBe(true);
		expect(isKnownAction("file", "READ")).toBe(true);
	});

	it("returns false for unknown actions", () => {
		expect(isKnownAction("http", "bulkPost")).toBe(false);
		expect(isKnownAction("database", "bulkInsert")).toBe(false);
		expect(isKnownAction("file", "append")).toBe(false);
	});

	it("always returns true for mcp (dynamic actions)", () => {
		expect(isKnownAction("mcp", "anything")).toBe(true);
		expect(isKnownAction("mcp", "custom_tool_name")).toBe(true);
	});
});

describe("isWriteAction", () => {
	it("returns false for read-only actions", () => {
		expect(isWriteAction("http", "get")).toBe(false);
		expect(isWriteAction("file", "read")).toBe(false);
		expect(isWriteAction("database", "query")).toBe(false);
	});

	it("returns true for write actions", () => {
		expect(isWriteAction("http", "post")).toBe(true);
		expect(isWriteAction("file", "write")).toBe(true);
		expect(isWriteAction("database", "mutate")).toBe(true);
	});

	it("returns true for execute actions", () => {
		expect(isWriteAction("shell", "exec")).toBe(true);
		expect(isWriteAction("database", "exec")).toBe(true);
	});

	it("returns true for unknown actions (fail-closed)", () => {
		expect(isWriteAction("database", "bulkInsert")).toBe(true);
		expect(isWriteAction("http", "custom")).toBe(true);
	});
});
