import { existsSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline";

const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const GREEN = "\x1b[32m";
const CYAN = "\x1b[36m";
const YELLOW = "\x1b[33m";
const RESET = "\x1b[0m";

interface Choice {
	key: string;
	label: string;
	preset?: string;
	autoScope?: boolean;
}

const CHOICES: Choice[] = [
	{ key: "1", label: "Research agent (web search, summarization)", preset: "safe-research" },
	{
		key: "2",
		label: "Coding assistant (file read/write in workspace)",
		preset: "workspace-assistant",
	},
	{ key: "3", label: "RAG system (document retrieval, embeddings)", preset: "rag-reader" },
	{ key: "4", label: "Automation bot (APIs, databases, workflows)", preset: "automation-agent" },
	{ key: "5", label: "Auto-detect per task (AutoScope)", autoScope: true },
];

type EnforcementMode = "sidecar" | "embedded";

function ask(question: string): Promise<string> {
	const rl = createInterface({ input: process.stdin, output: process.stdout });
	return new Promise((resolve) => {
		rl.question(question, (answer) => {
			rl.close();
			resolve(answer.trim());
		});
	});
}

function generateConfig(choice: Choice, mode: EnforcementMode): string {
	const base = choice.autoScope ? { autoScope: true } : { preset: choice.preset };
	if (mode === "sidecar") {
		return JSON.stringify(
			{
				...base,
				mode: "sidecar",
				sidecar: {
					baseUrl: "http://localhost:8787",
					authToken: "${SIDECAR_TOKEN}",
				},
			},
			null,
			2,
		);
	}
	return JSON.stringify({ ...base, mode: "embedded" }, null, 2);
}

function generateSnippet(choice: Choice, mode: EnforcementMode): string {
	const presetLine = choice.autoScope
		? "const kernel = createKernel({ autoScope: true, mode: 'embedded' })"
		: `const kernel = createKernel({ preset: "${choice.preset}", mode: '${mode}'${
				mode === "sidecar"
					? `,\n  sidecar: { baseUrl: 'http://localhost:8787', authToken: process.env.SIDECAR_TOKEN }`
					: ""
			} })`;

	const modeNote =
		mode === "sidecar"
			? "// Sidecar mode: tools execute in the sidecar process. Start sidecar first.\n// See: https://arikernel.dev/docs/sidecar-mode\n"
			: "// Embedded mode: tools run in-process. For development / trusted environments only.\n";

	return `import { createKernel } from "@arikernel/runtime"
import { protectTools } from "@arikernel/adapters"

${modeNote}
${presetLine}

const tools = protectTools({
  web_search: { toolClass: "http", action: "get" },
  read_file:  { toolClass: "file", action: "read" },
}, { kernel })`;
}

export async function runInit(): Promise<void> {
	const configPath = "arikernel.config.json";

	if (existsSync(configPath)) {
		console.log(`${YELLOW}Config already exists: ${configPath}${RESET}`);
		console.log(`${DIM}Delete it first to re-initialize.${RESET}`);
		return;
	}

	console.log(`\n${CYAN}${BOLD}AriKernel Setup${RESET}\n`);
	console.log(`${BOLD}What type of agent are you building?${RESET}\n`);

	for (const choice of CHOICES) {
		console.log(`  ${BOLD}${choice.key})${RESET} ${choice.label}`);
	}

	console.log("");
	const answer = await ask(`${DIM}Enter choice [1-5]:${RESET} `);
	const selected = CHOICES.find((c) => c.key === answer);

	if (!selected) {
		console.log(`\n${YELLOW}Invalid choice. Using safe defaults (safe-research).${RESET}`);
		const fallback = CHOICES[0];
		writeFileSync(configPath, generateConfig(fallback, "sidecar"), "utf-8");
		console.log(`${GREEN}Created ${configPath}${RESET}\n`);
		return;
	}

	// ── Mode selection ───────────────────────────────────────────────
	console.log(`\n${BOLD}Enforcement mode:${RESET}\n`);
	console.log(
		`  ${BOLD}1)${RESET} Sidecar ${GREEN}(recommended)${RESET} — tools execute in an isolated process. Strongest enforcement.`,
	);
	console.log(
		`  ${BOLD}2)${RESET} Embedded ${YELLOW}(dev / trusted environments only)${RESET} — tools run in-process. Cooperative enforcement.`,
	);
	console.log("");

	const modeAnswer = await ask(`${DIM}Enter choice [1-2, default: 1]:${RESET} `);
	const mode: EnforcementMode = modeAnswer === "2" ? "embedded" : "sidecar";

	if (mode === "embedded") {
		console.log(
			`\n${YELLOW}Note: embedded mode is cooperative — the host process can bypass enforcement.${RESET}`,
		);
		console.log(`${YELLOW}Use sidecar mode for production deployments.${RESET}`);
	}

	const config = generateConfig(selected, mode);
	writeFileSync(configPath, config, "utf-8");

	console.log(`\n${GREEN}${BOLD}Created ${configPath}${RESET}`);
	console.log(`${DIM}${config}${RESET}\n`);

	if (mode === "sidecar") {
		console.log(`${CYAN}${BOLD}Next step — start the sidecar:${RESET}`);
		console.log(
			`${DIM}  SIDECAR_TOKEN=<your-token> npx tsx examples/sidecar-secure/server.ts${RESET}\n`,
		);
	}

	console.log(`${CYAN}${BOLD}Quick start:${RESET}\n`);
	console.log(generateSnippet(selected, mode));
	console.log("");
}
