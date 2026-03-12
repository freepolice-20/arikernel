import { type Server, createServer } from "node:http";
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
	private readonly server: Server;
	private readonly registry: PrincipalRegistry;
	private readonly rateLimiter: RateLimiter;
	private readonly port: number;
	private readonly host: string;

	constructor(config: SidecarConfig) {
		this.port = config.port ?? DEFAULT_PORT;
		this.host = config.host ?? DEFAULT_HOST;
		const authToken = config.authToken;
		const principals = config.principals;

		// Dev mode = no `principals` configured; clients supply their own principalId.
		// This is unsafe in production — fail fast so misconfigurations are caught at startup.
		if (!principals) {
			if (process.env.NODE_ENV === "production") {
				throw new Error(
					"AriKernel: dev mode cannot be enabled in production. " +
						"Configure `principals` with per-principal API keys for production deployments.",
				);
			}
			console.warn(
				"[AriKernel] DEV MODE active: authentication is relaxed. " + "Do not use in production.",
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
		let decisionDelegate: DecisionDelegate | undefined;
		if (config.decisionMode === "remote") {
			if (!config.controlPlaneUrl) {
				throw new Error("controlPlaneUrl is required when decisionMode is 'remote'");
			}
			decisionDelegate = new DecisionDelegate({
				controlPlaneUrl: config.controlPlaneUrl,
				controlPlaneAuthToken: config.controlPlaneAuthToken,
				controlPlaneTimeoutMs: config.controlPlaneTimeoutMs,
			});
		}

		this.server = createServer((req, res) => {
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
		});
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
		return `http://${this.host}:${this.port}`;
	}
}

export function createSidecarServer(config: SidecarConfig): SidecarServer {
	return new SidecarServer(config);
}
