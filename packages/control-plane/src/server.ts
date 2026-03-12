import { createHash } from "node:crypto";
import { type Server, createServer } from "node:http";
import type { PolicyRule } from "@arikernel/core";
import { PolicyEngine } from "@arikernel/policy-engine";
import { ControlPlaneAuditStore } from "./audit-store.js";
import {
	handleDecision,
	handleHealth,
	handleTaintQuery,
	handleTaintRegister,
	rejectUnauthorized,
} from "./router.js";
import { DecisionSigner, NonceStore } from "./signer.js";
import { GlobalTaintRegistry } from "./taint-registry.js";
import type { ControlPlaneConfig } from "./types.js";

export const DEFAULT_CP_PORT = 9090;
export const DEFAULT_CP_HOST = "127.0.0.1";

/**
 * Compute a stable SHA-256 hash prefix for the loaded policy ruleset.
 * Used for policy versioning in signed decision receipts.
 */
function computePolicyHash(policy: string | PolicyRule[] | undefined): string {
	const input =
		policy == null ? "[]" : typeof policy === "string" ? policy : JSON.stringify(policy);
	return createHash("sha256").update(input).digest("hex").slice(0, 16);
}

export class ControlPlaneServer {
	private readonly server: Server;
	private readonly port: number;
	private readonly host: string;
	private readonly engine: PolicyEngine;
	private readonly signer: DecisionSigner;
	private readonly taintRegistry: GlobalTaintRegistry;
	private readonly auditStore: ControlPlaneAuditStore;
	private readonly requestNonceStore: NonceStore;
	private readonly config: ControlPlaneConfig;
	private readonly _policyHash: string;

	constructor(config: ControlPlaneConfig) {
		this.port = config.port ?? DEFAULT_CP_PORT;
		this.host = config.host ?? DEFAULT_CP_HOST;
		this.config = config;
		this.engine = new PolicyEngine(config.policy);
		this.signer = new DecisionSigner(config.signingKey);
		this.taintRegistry = new GlobalTaintRegistry();
		this.auditStore = new ControlPlaneAuditStore(config.auditLog ?? ":memory:");
		this.requestNonceStore = new NonceStore();
		this._policyHash = computePolicyHash(config.policy);

		const authToken = config.authToken;

		this.server = createServer((req, res) => {
			const url = req.url ?? "/";
			const method = req.method ?? "GET";

			if (method === "GET" && url === "/health") {
				handleHealth(res);
				return;
			}

			// Authenticate all non-health endpoints
			if (authToken) {
				if (rejectUnauthorized(req, res, authToken)) return;
			}

			let handler: Promise<void> | undefined;

			if (method === "POST" && url === "/decision") {
				handler = handleDecision(
					req,
					res,
					this.engine,
					this.signer,
					this.taintRegistry,
					this.config,
					this.auditStore,
					this._policyHash,
					this.requestNonceStore,
				);
			} else if (method === "POST" && url === "/taint/register") {
				handler = handleTaintRegister(req, res, this.taintRegistry);
			} else if (method === "POST" && url === "/taint/query") {
				handler = handleTaintQuery(req, res, this.taintRegistry);
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
		return new Promise((resolve) => {
			this.server.closeAllConnections();
			this.server.close(() => {
				this.auditStore.close();
				resolve();
			});
		});
	}

	get address(): string {
		return `http://${this.host}:${this.port}`;
	}

	/** Read-only access to the persistent audit store. */
	get audit(): ControlPlaneAuditStore {
		return this.auditStore;
	}

	/** Read-only access to the global taint registry. */
	get taints(): GlobalTaintRegistry {
		return this.taintRegistry;
	}

	/** The server's Ed25519 public key (hex). Clients use this to verify signatures. */
	get publicKeyHex(): string {
		return this.signer.publicKeyHex;
	}

	/** SHA-256 prefix hash of the loaded policy rules. */
	get policyHash(): string {
		return this._policyHash;
	}
}

export function createControlPlaneServer(config: ControlPlaneConfig): ControlPlaneServer {
	return new ControlPlaneServer(config);
}
