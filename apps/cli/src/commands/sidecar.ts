import { DEFAULT_HOST, DEFAULT_PORT, SidecarServer } from "@arikernel/sidecar";

export async function runSidecar(options: {
	policy: string;
	port: number;
	host: string;
	auditLog: string;
	authToken?: string;
	tlsCert?: string;
	tlsKey?: string;
}): Promise<void> {
	if (options.tlsCert && !options.tlsKey) {
		throw new Error("--tls-key is required when --tls-cert is provided");
	}
	if (options.tlsKey && !options.tlsCert) {
		throw new Error("--tls-cert is required when --tls-key is provided");
	}

	const server = new SidecarServer({
		port: options.port,
		host: options.host,
		policy: options.policy,
		auditLog: options.auditLog,
		authToken: options.authToken,
		tlsCert: options.tlsCert,
		tlsKey: options.tlsKey,
	});

	await server.listen();

	const proto = options.tlsCert ? "https" : "http";
	const addr = `${options.host}:${options.port}`;
	console.log(`AriKernel sidecar listening on ${addr}`);
	console.log(`  Policy : ${options.policy}`);
	console.log(`  Audit  : ${options.auditLog}`);
	console.log(`  Auth   : ${options.authToken ? "enabled (Bearer token)" : "disabled"}`);
	console.log(`  TLS    : ${options.tlsCert ? "enabled" : "disabled"}`);
	console.log(`  POST   : ${proto}://${addr}/execute`);
	console.log(`  Health : ${proto}://${addr}/health`);

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
