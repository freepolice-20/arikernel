/**
 * ARI Kernel Sidecar Launcher
 * Called by the OpenClaw ari-kernel plugin to start the security sidecar.
 * Run from: C:\Users\manri\Ari Kernel\
 */
import { createSidecarServer } from "@arikernel/sidecar";
import { mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

const AUDIT_DIR = join(homedir(), ".openclaw", "ari-kernel");
const AUDIT_DB = join(AUDIT_DIR, "audit.db");
const PORT = parseInt(process.env.ARI_KERNEL_PORT ?? "8787", 10);

if (!existsSync(AUDIT_DIR)) {
  mkdirSync(AUDIT_DIR, { recursive: true });
}

const server = createSidecarServer({
  port: PORT,
  host: "127.0.0.1",
  preset: "workspace-assistant",
  auditLog: AUDIT_DB,
  runStatePolicy: {
    maxDeniedSensitiveActions: 5,
    behavioralRules: true,
  },
});

await server.listen();
console.log(`[ARI Kernel] Sidecar ready on http://127.0.0.1:${PORT}`);

// Signal parent that we're ready (if launched as child process)
if (process.send) process.send("ready");

// Graceful shutdown
process.on("SIGTERM", () => server.close().then(() => process.exit(0)));
process.on("SIGINT",  () => server.close().then(() => process.exit(0)));
