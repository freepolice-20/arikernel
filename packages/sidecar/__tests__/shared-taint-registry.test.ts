import { normalize, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { type SharedStoreConfig, SharedTaintRegistry } from "../src/shared-taint-registry.js";

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
		expect(c?.principalId).toBe("agent-B");
		expect(c?.key).toBe("db:tasks");
	});

	it("extractResourceKey returns db key for shared table write", () => {
		const reg = new SharedTaintRegistry(config);
		const key = reg.extractResourceKey("database", "insert", { table: "messages" });
		expect(key).toBe("db:messages");
	});

	it("extractResourceKey returns db key with database prefix for shared database write", () => {
		const reg = new SharedTaintRegistry(config);
		const key = reg.extractResourceKey("database", "update", {
			table: "logs",
			database: "shared_db",
		});
		expect(key).toBe("db:shared_db.logs");
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

describe("SharedTaintRegistry TTL expiry", () => {
	beforeEach(() => {
		vi.useFakeTimers();
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it("entry is available before TTL expires", () => {
		const reg = new SharedTaintRegistry({ contaminationTtlMs: 5000 });
		reg.markContaminated("db:messages", "agent-A");
		expect(reg.isContaminated("db:messages")).toBe(true);
		expect(reg.getContamination("db:messages")).toBeDefined();
	});

	it("entry expires after TTL", () => {
		const reg = new SharedTaintRegistry({ contaminationTtlMs: 5000 });
		reg.markContaminated("db:messages", "agent-A");

		vi.advanceTimersByTime(4999);
		expect(reg.isContaminated("db:messages")).toBe(true);

		vi.advanceTimersByTime(2);
		expect(reg.isContaminated("db:messages")).toBe(false);
		expect(reg.getContamination("db:messages")).toBeUndefined();
	});

	it("re-contamination refreshes TTL", () => {
		const reg = new SharedTaintRegistry({ contaminationTtlMs: 5000 });
		reg.markContaminated("db:messages", "agent-A");

		vi.advanceTimersByTime(3000);
		// Refresh
		reg.markContaminated("db:messages", "agent-B");

		vi.advanceTimersByTime(3000);
		// Would have expired under original TTL, but refresh extends it
		expect(reg.isContaminated("db:messages")).toBe(true);
		expect(reg.getContamination("db:messages")?.principalId).toBe("agent-B");

		vi.advanceTimersByTime(2001);
		expect(reg.isContaminated("db:messages")).toBe(false);
	});

	it("default TTL is 1 hour", () => {
		const reg = new SharedTaintRegistry({});
		reg.markContaminated("db:messages", "agent-A");

		vi.advanceTimersByTime(3_599_999);
		expect(reg.isContaminated("db:messages")).toBe(true);

		vi.advanceTimersByTime(2);
		expect(reg.isContaminated("db:messages")).toBe(false);
	});
});

describe("SharedTaintRegistry maxEntries eviction", () => {
	it("evicts oldest entry when maxEntries exceeded", () => {
		const reg = new SharedTaintRegistry({ maxContaminationEntries: 3 });
		reg.markContaminated("db:a", "agent-1");
		reg.markContaminated("db:b", "agent-2");
		reg.markContaminated("db:c", "agent-3");
		expect(reg.isContaminated("db:a")).toBe(true);

		// 4th entry should evict the oldest ("db:a")
		reg.markContaminated("db:d", "agent-4");
		expect(reg.isContaminated("db:a")).toBe(false);
		expect(reg.isContaminated("db:b")).toBe(true);
		expect(reg.isContaminated("db:c")).toBe(true);
		expect(reg.isContaminated("db:d")).toBe(true);
	});

	it("re-contamination refreshes insertion order (LRU)", () => {
		const reg = new SharedTaintRegistry({ maxContaminationEntries: 3 });
		reg.markContaminated("db:a", "agent-1");
		reg.markContaminated("db:b", "agent-2");
		reg.markContaminated("db:c", "agent-3");

		// Refresh "db:a" — moves it to end
		reg.markContaminated("db:a", "agent-1-refreshed");

		// "db:b" is now oldest — should be evicted
		reg.markContaminated("db:d", "agent-4");
		expect(reg.isContaminated("db:a")).toBe(true);
		expect(reg.isContaminated("db:b")).toBe(false);
		expect(reg.isContaminated("db:c")).toBe(true);
		expect(reg.isContaminated("db:d")).toBe(true);
	});

	it("default maxEntries is 10000", () => {
		const reg = new SharedTaintRegistry({});
		// Just verify it doesn't evict at reasonable sizes
		for (let i = 0; i < 100; i++) {
			reg.markContaminated(`db:table_${i}`, `agent-${i}`);
		}
		expect(reg.isContaminated("db:table_0")).toBe(true);
		expect(reg.isContaminated("db:table_99")).toBe(true);
	});
});
