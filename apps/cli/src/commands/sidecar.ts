import { SidecarServer, DEFAULT_PORT } from '@arikernel/sidecar';

export async function runSidecar(options: {
	policy: string;
	port: number;
	auditLog: string;
}): Promise<void> {
	const server = new SidecarServer({
		port: options.port,
		policy: options.policy,
		auditLog: options.auditLog,
	});

	await server.listen();

	console.log(`AriKernel sidecar listening on port ${options.port}`);
	console.log(`  Policy : ${options.policy}`);
	console.log(`  Audit  : ${options.auditLog}`);
	console.log(`  POST   : http://localhost:${options.port}/execute`);
	console.log(`  Health : http://localhost:${options.port}/health`);
	console.log('\nPress Ctrl+C to stop.\n');

	// Keep the process alive; shut down cleanly on SIGINT/SIGTERM
	const shutdown = async () => {
		console.log('\nShutting down sidecar...');
		await server.close();
		process.exit(0);
	};

	process.on('SIGINT', shutdown);
	process.on('SIGTERM', shutdown);

	// Block indefinitely
	await new Promise<never>(() => {});
}
