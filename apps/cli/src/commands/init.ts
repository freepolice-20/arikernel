import { writeFileSync, existsSync } from 'node:fs';
import { createInterface } from 'node:readline';

const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const GREEN = '\x1b[32m';
const CYAN = '\x1b[36m';
const YELLOW = '\x1b[33m';
const RESET = '\x1b[0m';

interface Choice {
	key: string;
	label: string;
	preset?: string;
	autoScope?: boolean;
}

const CHOICES: Choice[] = [
	{ key: '1', label: 'Research agent (web search, summarization)', preset: 'safe-research' },
	{ key: '2', label: 'Coding assistant (file read/write in workspace)', preset: 'workspace-assistant' },
	{ key: '3', label: 'RAG system (document retrieval, embeddings)', preset: 'rag-reader' },
	{ key: '4', label: 'Automation bot (APIs, databases, workflows)', preset: 'automation-agent' },
	{ key: '5', label: 'Auto-detect per task (AutoScope)', autoScope: true },
];

function ask(question: string): Promise<string> {
	const rl = createInterface({ input: process.stdin, output: process.stdout });
	return new Promise((resolve) => {
		rl.question(question, (answer) => {
			rl.close();
			resolve(answer.trim());
		});
	});
}

function generateConfig(choice: Choice): string {
	if (choice.autoScope) {
		return JSON.stringify({ autoScope: true }, null, 2);
	}
	return JSON.stringify({ preset: choice.preset }, null, 2);
}

function generateSnippet(choice: Choice): string {
	const presetLine = choice.autoScope
		? 'const kernel = createKernel({ autoScope: true })'
		: `const kernel = createKernel({ preset: "${choice.preset}" })`;

	return `import { createKernel } from "@arikernel/runtime"
import { protectTools } from "@arikernel/adapters"

${presetLine}

const tools = protectTools({
  web_search: { toolClass: "http", action: "get" },
  read_file:  { toolClass: "file", action: "read" },
}, { kernel })`;
}

export async function runInit(): Promise<void> {
	const configPath = 'arikernel.config.json';

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

	console.log('');
	const answer = await ask(`${DIM}Enter choice [1-5]:${RESET} `);
	const selected = CHOICES.find((c) => c.key === answer);

	if (!selected) {
		console.log(`\n${YELLOW}Invalid choice. Using safe defaults (safe-research).${RESET}`);
		const fallback = CHOICES[0];
		writeFileSync(configPath, generateConfig(fallback), 'utf-8');
		console.log(`${GREEN}Created ${configPath}${RESET}\n`);
		return;
	}

	const config = generateConfig(selected);
	writeFileSync(configPath, config, 'utf-8');

	console.log(`\n${GREEN}${BOLD}Created ${configPath}${RESET}`);
	console.log(`${DIM}${config}${RESET}\n`);

	console.log(`${CYAN}${BOLD}Quick start:${RESET}\n`);
	console.log(generateSnippet(selected));
	console.log('');
}
