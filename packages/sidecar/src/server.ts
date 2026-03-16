import { readFileSync } from "node:fs";
import { type Server as HttpServer, createServer } from "node:http";
import { type Server as HttpsServer, createServer as createTlsServer } from "node:https";
import { dirname, resolve } from "node:path";
import { DecisionDelegate } from "./decision-delegate.js";
import { RateLimiter } from "./rate-limiter.js";
import { PrincipalRegistry, resolveRegistryConfig } from "./registry.js";
import {
	handleExecute,
	handleHealth,
	handleRequestCapability,
	handleStatus,
	rejectUnauthorized,
	resolvePrincipal,
} from "./router.js";
import type { PrincipalCredentials, SidecarConfig } from "./types.js";

export const DEFAULT_PORT = 8787;
export const DEFAULT_HOST = "127.0.0.1";

/**
 * Request context resolved by the authentication layer.
 * Passed to handlers so they never trust client-supplied principalId directly.
 */
export interface AuthContext {
	/** The authenticated principalId (from API key lookup or dev-mode body). */
	principalId?: string;
	/** Whether identity was bound via API key (true) or client-supplied (false). */
	authenticated: boolean;
}

export class SidecarServer {
	private readonly server: HttpServer | HttpsServer;
	private readonly registry: PrincipalRegistry;
	private readonly rateLimiter: RateLimiter;
	private readonly port: number;
	private readonly host: string;
	private readonly tls: boolean;

	constructor(config: SidecarConfig) {
		this.port = config.port ?? DEFAULT_PORT;
		this.host = config.host ?? DEFAULT_HOST;
		const authToken = config.authToken;
		const principals = config.principals;

		// Dev mode = no `principals` configured; clients supply their own principalId.
		// This is unsafe in production — multiple layers of defense prevent misuse:
		// 1. NODE_ENV=production → hard error
		// 2. Non-loopback bind → hard error (prevents network exposure)
		// 3. Loud startup warning for local use
		if (!principals) {
			if (process.env.NODE_ENV === "production") {
				throw new Error(
					"AriKernel: dev mode cannot be enabled in production. " +
						"Configure `principals` with per-principal API keys for production deployments.",
				);
			}
			if (!isLoopback(this.host)) {
				throw new Error(
					`AriKernel: dev mode cannot bind to '${this.host}'. ` +
						"Without authentication, only loopback addresses (127.0.0.1, ::1, localhost) are allowed. " +
						"Configure `principals` with per-principal API keys to bind to non-loopback interfaces.",
				);
			}
			console.warn(
				"[AriKernel] ⚠ DEV MODE — no authentication. " +
					"Restricted to loopback interface. " +
					"Configure `principals` for production use.",
			);
		}

		const registryConfig = resolveRegistryConfig({
			policy: config.policy,
			preset: config.preset,
			capabilities: config.capabilities,
			runStatePolicy: config.runStatePolicy,
			signingKey: config.signingKey,
			securityMode: config.securityMode,
			sharedStoreConfig: config.sharedStoreConfig,
			correlatorConfig: config.correlatorConfig,
			onCrossPrincipalAlert: config.onCrossPrincipalAlert,
		});

		const auditDir = dirname(resolve(config.auditLog ?? "./sidecar-audit.db"));
		this.registry = new PrincipalRegistry(auditDir, registryConfig);
		this.rateLimiter = new RateLimiter(config.rateLimits);

		// Remote decision delegation: when decisionMode is 'remote', the sidecar
		// calls the control plane for policy decisions before executing tools.
		// EXPERIMENTAL: Remote mode adds network latency, availability dependency,
		// and receipt-substitution attack surface. Local mode is recommended.
		let decisionDelegate: DecisionDelegate | undefined;
		if (config.decisionMode === "remote") {
			console.warn(
				"[AriKernel] WARNING: decisionMode 'remote' is experimental. " +
					"Local sidecar enforcement is the recommended production default. " +
					"Remote mode adds latency, availability risk, and receipt-substitution surface. " +
					"See docs/control-plane.md for migration guidance.",
			);
			if (!config.controlPlaneUrl) {
				throw new Error("controlPlaneUrl is required when decisionMode is 'remote'");
			}
			if (!config.controlPlanePublicKey) {
				console.warn(
					"[AriKernel] WARNING: controlPlanePublicKey is not configured. " +
						"Without signature verification, remote decisions are vulnerable to tampering. " +
						"This is strongly discouraged even in non-production environments.",
				);
			}
			decisionDelegate = new DecisionDelegate({
				controlPlaneUrl: config.controlPlaneUrl,
				controlPlaneAuthToken: config.controlPlaneAuthToken,
				controlPlaneTimeoutMs: config.controlPlaneTimeoutMs,
				controlPlanePublicKey: config.controlPlanePublicKey,
			});
		}

		// TLS: when cert + key are provided, serve HTTPS instead of HTTP.
		this.tls = !!(config.tlsCert && config.tlsKey);
		const requestHandler = (
			req: import("node:http").IncomingMessage,
			res: import("node:http").ServerResponse,
		) => {
			const url = req.url ?? "/";
			const method = req.method ?? "GET";

			// Health endpoint is always unauthenticated (liveness probes)
			if (method === "GET" && url === "/health") {
				handleHealth(res);
				return;
			}

			// Authentication: principal-keyed mode takes precedence over shared authToken
			let authCtx: AuthContext;
			if (principals) {
				const resolved = resolvePrincipal(req, res, principals);
				if (!resolved) return; // response already sent (401/403)
				authCtx = { principalId: resolved, authenticated: true };
			} else if (authToken) {
				if (rejectUnauthorized(req, res, authToken)) return;
				authCtx = { authenticated: false };
			} else {
				authCtx = { authenticated: false };
			}

			let handler: Promise<void> | undefined;

			if (method === "POST" && url === "/execute") {
				handler = handleExecute(
					req,
					res,
					this.registry,
					authCtx,
					this.rateLimiter,
					decisionDelegate,
				);
			} else if (method === "POST" && url === "/request-capability") {
				handler = handleRequestCapability(req, res, this.registry, authCtx, this.rateLimiter);
			} else if (method === "POST" && url === "/status") {
				handler = handleStatus(req, res, this.registry, authCtx);
			}

			if (handler) {
				handler.catch(() => {
					if (!res.headersSent) {
						res.writeHead(500, { "Content-Type": "application/json" });
						res.end(JSON.stringify({ error: "Internal server error" }));
					}
				});
				return;
			}

			res.writeHead(404, { "Content-Type": "application/json" });
			res.end(JSON.stringify({ error: "Not found" }));
		};

		if (this.tls) {
			this.server = createTlsServer(
				{
					cert: readFileSync(config.tlsCert!),
					key: readFileSync(config.tlsKey!),
				},
				requestHandler,
			);
		} else {
			this.server = createServer(requestHandler);
		}
	}

	listen(): Promise<void> {
		return new Promise((resolve) => {
			this.server.listen(this.port, this.host, () => resolve());
		});
	}

	close(): Promise<void> {
		return new Promise((resolve, reject) => {
			this.registry.closeAll();
			// Force-close idle keep-alive connections so the port is released immediately
			this.server.closeAllConnections();
			this.server.close((err) => {
				if (err) reject(err);
				else resolve();
			});
		});
	}

	get address(): string {
		const proto = this.tls ? "https" : "http";
		return `${proto}://${this.host}:${this.port}`;
	}
}

export function createSidecarServer(config: SidecarConfig): SidecarServer {
	return new SidecarServer(config);
}

/** Check whether a host string resolves to a loopback-only interface. */
function isLoopback(host: string): boolean {
	const h = host.trim().toLowerCase();
	return h === "127.0.0.1" || h === "::1" || h === "localhost" || h === "";
}
