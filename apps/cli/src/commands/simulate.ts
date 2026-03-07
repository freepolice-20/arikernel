import { runSimulation, generateReport } from '@arikernel/attack-sim';

export async function runSimulate(policyPath: string): Promise<void> {
	console.log('Running attack simulation pack...\n');

	const results = await runSimulation(policyPath);
	const report = generateReport(results);

	console.log(report);
}
