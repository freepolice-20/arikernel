/**
 * Ari Kernel — Secure Sidecar Server
 *
 * Production-grade sidecar deployment using preset-based configuration.
 * The sidecar owns all tool execution — agents communicate exclusively
 * via HTTP and have no direct access to tools, policies, or audit state.
 *
 * This is the highest-assurance deployment mode when all side-effectful
 * operations are routed exclusively through the sidecar.
 *
 *   pnpm example:sidecar-secure
 *
 * Or start the server standalone:
 *   npx tsx examples/sidecar-secure/server.ts
 */

import { SidecarServer } from "@arikernel/sidecar";

const PORT = 18_801;

// ── One-liner: preset + auth ────────────────────────────────────────
// The "safe" preset provides:
//   - HTTP GET allowed (outbound writes denied)
//   - File reads restricted to ./data/**
//   - Shell execution denied
//   - Behavioral rules enabled (quarantine on attack patterns)
//   - Taint tracking for web, RAG, and email sources

const server = new SidecarServer({
	port: PORT,
	preset: "safe",
	authToken: process.env.AUTH_TOKEN ?? "demo-token-do-not-use-in-production",
	auditLog: "./sidecar-secure-audit.db",
});

await server.listen();
console.log(`\nAri Kernel sidecar (secure mode) listening on http://127.0.0.1:${PORT}`);
console.log("Preset: safe | Auth: Bearer token required | Audit: sidecar-secure-audit.db\n");

// In production, the server runs indefinitely. For the demo, we export
// the server instance so the agent script can shut it down after the demo.
export { server, PORT };
