import { createServer, type Server } from 'node:http';
import { resolve, dirname } from 'node:path';
import { PrincipalRegistry } from './registry.js';
import { handleExecute, handleStatus, handleHealth, rejectUnauthorized } from './router.js';
import type { SidecarConfig } from './types.js';

export const DEFAULT_PORT = 8787;
export const DEFAULT_HOST = '127.0.0.1';

export class SidecarServer {
	private readonly server: Server;
	private readonly registry: PrincipalRegistry;
	private readonly port: number;
	private readonly host: string;

	constructor(config: SidecarConfig) {
		this.port = config.port ?? DEFAULT_PORT;
		this.host = config.host ?? DEFAULT_HOST;
		const authToken = config.authToken;

		const auditDir = dirname(resolve(config.auditLog ?? './sidecar-audit.db'));
		this.registry = new PrincipalRegistry(auditDir, config.policy, config.runStatePolicy);

		this.server = createServer((req, res) => {
			const url = req.url ?? '/';
			const method = req.method ?? 'GET';

			// Health endpoint is always unauthenticated (liveness probes)
			if (method === 'GET' && url === '/health') {
				handleHealth(res);
				return;
			}

			// Authenticate all other endpoints when authToken is configured
			if (authToken && rejectUnauthorized(req, res, authToken)) {
				return;
			}

			let handler: Promise<void> | undefined;

			if (method === 'POST' && url === '/execute') {
				handler = handleExecute(req, res, this.registry);
			} else if (method === 'POST' && url === '/status') {
				handler = handleStatus(req, res, this.registry);
			}

			if (handler) {
				handler.catch(() => {
					if (!res.headersSent) {
						res.writeHead(500, { 'Content-Type': 'application/json' });
						res.end(JSON.stringify({ error: 'Internal server error' }));
					}
				});
				return;
			}

			res.writeHead(404, { 'Content-Type': 'application/json' });
			res.end(JSON.stringify({ error: 'Not found' }));
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
