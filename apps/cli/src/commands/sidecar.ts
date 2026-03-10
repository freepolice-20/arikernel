import { DEFAULT_HOST, DEFAULT_PORT, SidecarServer } from "@arikernel/sidecar";

export async function runSidecar(options: {
	policy: string;
	port: number;
	host: string;
	auditLog: string;
	authToken?: string;
}): Promise<void> {
	const server = new SidecarServer({
		port: options.port,
		host: options.host,
		policy: options.policy,
		auditLog: options.auditLog,
		authToken: options.authToken,
	});

	await server.listen();

	const addr = `${options.host}:${options.port}`;
	console.log(`AriKernel sidecar listening on ${addr}`);
	console.log(`  Policy : ${options.policy}`);
	console.log(`  Audit  : ${options.auditLog}`);
	console.log(`  Auth   : ${options.authToken ? "enabled (Bearer token)" : "disabled"}`);
	console.log(`  POST   : http://${addr}/execute`);
	console.log(`  Health : http://${addr}/health`);

	if (options.host !== DEFAULT_HOST) {
		console.log(`\n  ⚠  Server is exposed on ${options.host}. Ensure --auth-token is set.`);
	}

	console.log("\nPress Ctrl+C to stop.\n");

	// Keep the process alive; shut down cleanly on SIGINT/SIGTERM
	const shutdown = async () => {
		console.log("\nShutting down sidecar...");
		await server.close();
		process.exit(0);
	};

	process.on("SIGINT", shutdown);
	process.on("SIGTERM", shutdown);

	// Block indefinitely
	await new Promise<never>(() => {});
}
