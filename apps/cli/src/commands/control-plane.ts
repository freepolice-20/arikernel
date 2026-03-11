import { writeFileSync } from "node:fs";
import { ControlPlaneAuditStore } from "@arikernel/control-plane";

export function runExportAudit(dbPath: string, outPath?: string): void {
	let store: ControlPlaneAuditStore;
	try {
		store = new ControlPlaneAuditStore(dbPath);
	} catch (e) {
		console.error(`Error: Cannot open audit database '${dbPath}': ${(e as Error).message}`);
		process.exitCode = 1;
		return;
	}

	const jsonl = store.exportJsonl();
	const rowCount = store.count;
	store.close();

	if (outPath) {
		try {
			writeFileSync(outPath, jsonl, "utf-8");
			console.log(`Exported ${rowCount} audit records to ${outPath}`);
		} catch (e) {
			console.error(`Error: Cannot write to '${outPath}': ${(e as Error).message}`);
			process.exitCode = 1;
		}
	} else {
		process.stdout.write(jsonl);
	}
}
