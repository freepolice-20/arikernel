import { createServer, type Server } from 'node:http';
import { resolve, dirname } from 'node:path';
import { PrincipalRegistry } from './registry.js';
import { handleExecute, handleStatus, handleHealth } from './router.js';
import type { SidecarConfig } from './types.js';

export const DEFAULT_PORT = 8787;

export class SidecarServer {
	private readonly server: Server;
	private readonly registry: PrincipalRegistry;
	private readonly port: number;

	constructor(config: SidecarConfig) {
		this.port = config.port ?? DEFAULT_PORT;

		const auditDir = dirname(resolve(config.auditLog ?? './sidecar-audit.db'));
		this.registry = new PrincipalRegistry(auditDir, config.policy, config.runStatePolicy);

		this.server = createServer((req, res) => {
			const url = req.url ?? '/';
			const method = req.method ?? 'GET';

			if (method === 'GET' && url === '/health') {
				handleHealth(res);
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
			this.server.listen(this.port, () => resolve());
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
		return `http://localhost:${this.port}`;
	}
}

export function createSidecarServer(config: SidecarConfig): SidecarServer {
	return new SidecarServer(config);
}
