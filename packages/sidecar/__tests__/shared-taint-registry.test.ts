import { resolve, normalize } from "node:path";
import { describe, expect, it } from "vitest";
import { SharedTaintRegistry, type SharedStoreConfig } from "../src/shared-taint-registry.js";

describe("SharedTaintRegistry", () => {
	const config: SharedStoreConfig = {
		sharedStorePaths: ["/shared/data"],
		sharedDatabases: ["shared_db"],
		sharedTables: ["messages", "tasks"],
	};

	it("markContaminated / isContaminated basic ops", () => {
		const reg = new SharedTaintRegistry(config);
		expect(reg.isContaminated("db:messages")).toBe(false);
		reg.markContaminated("db:messages", "agent-A");
		expect(reg.isContaminated("db:messages")).toBe(true);
	});

	it("getContamination returns metadata", () => {
		const reg = new SharedTaintRegistry(config);
		reg.markContaminated("db:tasks", "agent-B");
		const c = reg.getContamination("db:tasks");
		expect(c).toBeDefined();
		expect(c!.principalId).toBe("agent-B");
		expect(c!.key).toBe("db:tasks");
	});

	it("extractResourceKey returns db key for shared table write", () => {
		const reg = new SharedTaintRegistry(config);
		const key = reg.extractResourceKey("database", "insert", { table: "messages" });
		expect(key).toBe("db:messages");
	});

	it("extractResourceKey returns db key for shared database write", () => {
		const reg = new SharedTaintRegistry(config);
		const key = reg.extractResourceKey("database", "update", {
			table: "logs",
			database: "shared_db",
		});
		expect(key).toBe("db:logs");
	});

	it("extractResourceKey returns null for non-shared table", () => {
		const reg = new SharedTaintRegistry(config);
		const key = reg.extractResourceKey("database", "insert", { table: "private_notes" });
		expect(key).toBeNull();
	});

	it("extractResourceKey returns file key for shared path write", () => {
		const reg = new SharedTaintRegistry(config);
		const key = reg.extractResourceKey("file", "write", { path: "/shared/data/report.csv" });
		// Key is canonicalized: resolved + normalized path
		const expectedPath = normalize(resolve("/shared/data/report.csv"));
		expect(key).toBe(`file:${expectedPath}`);
	});

	it("extractResourceKey returns null for non-shared file path", () => {
		const reg = new SharedTaintRegistry(config);
		const key = reg.extractResourceKey("file", "write", { path: "/private/secret.txt" });
		expect(key).toBeNull();
	});

	it("extractResourceKey returns null for shell exec (not a shared write)", () => {
		const reg = new SharedTaintRegistry(config);
		const key = reg.extractResourceKey("shell", "exec", { command: "ls" });
		expect(key).toBeNull();
	});

	it("extractResourceKey returns db key for shared table read (query)", () => {
		const reg = new SharedTaintRegistry(config);
		const key = reg.extractResourceKey("database", "query", { table: "messages" });
		expect(key).toBe("db:messages");
	});

	it("case-insensitive table matching prevents bypass", () => {
		const reg = new SharedTaintRegistry(config);
		const key = reg.extractResourceKey("database", "insert", { table: "Messages" });
		expect(key).toBe("db:messages");
	});

	it("createDerivedSensitiveTaint produces correct label", () => {
		const label = SharedTaintRegistry.createDerivedSensitiveTaint("agent-X");
		expect(label.source).toBe("derived-sensitive");
		expect(label.origin).toBe("cross-principal:agent-X");
		expect(label.propagatedFrom).toBe("agent-X");
	});
});
