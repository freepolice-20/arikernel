import type { PresetId } from "@arikernel/core";

interface ScopeRule {
	preset: PresetId;
	keywords: string[];
	weight: number;
}

const SCOPE_RULES: ScopeRule[] = [
	{
		preset: "safe-research",
		weight: 1,
		keywords: [
			"search",
			"browse",
			"summarize",
			"summary",
			"webpage",
			"website",
			"url",
			"article",
			"research",
			"google",
			"fetch",
			"scrape",
			"crawl",
			"news",
			"lookup",
			"find online",
			"web",
			"internet",
			"link",
		],
	},
	{
		preset: "rag-reader",
		weight: 2,
		keywords: [
			"document",
			"pdf",
			"csv",
			"json",
			"analyze",
			"analysis",
			"parse",
			"extract",
			"read file",
			"corpus",
			"retrieval",
			"rag",
			"vector",
			"embedding",
			"index",
			"knowledge base",
			"ingest",
		],
	},
	{
		preset: "workspace-assistant",
		weight: 3,
		keywords: [
			"code",
			"refactor",
			"implement",
			"fix bug",
			"write code",
			"edit file",
			"create file",
			"repo",
			"repository",
			"git",
			"commit",
			"test",
			"build",
			"compile",
			"debug",
			"lint",
			"format",
			"workspace",
			"project",
		],
	},
	{
		preset: "automation-agent",
		weight: 4,
		keywords: [
			"automate",
			"automation",
			"workflow",
			"pipeline",
			"sync",
			"crm",
			"api",
			"webhook",
			"schedule",
			"trigger",
			"integrate",
			"integration",
			"send email",
			"notify",
			"database",
			"records",
			"batch",
			"process",
		],
	},
];

export interface ScopeResult {
	preset: PresetId;
	confidence: number;
	scores: Record<PresetId, number>;
}

export function classifyScope(task: string): ScopeResult {
	const lower = task.toLowerCase();
	const scores: Record<string, number> = {};

	for (const rule of SCOPE_RULES) {
		let score = 0;
		for (const keyword of rule.keywords) {
			if (lower.includes(keyword)) {
				score += 1;
			}
		}
		scores[rule.preset] = score;
	}

	let bestPreset: PresetId = "safe-research";
	let bestScore = 0;
	let totalScore = 0;

	for (const rule of SCOPE_RULES) {
		const score = scores[rule.preset];
		totalScore += score;
		if (score > bestScore) {
			bestScore = score;
			bestPreset = rule.preset;
		}
	}

	const confidence = totalScore > 0 ? bestScore / totalScore : 0;

	// If no keywords matched or confidence is too low, fall back to safe-research
	if (bestScore === 0 || confidence < 0.3) {
		return {
			preset: "safe-research",
			confidence: 0,
			scores: scores as Record<PresetId, number>,
		};
	}

	return {
		preset: bestPreset,
		confidence,
		scores: scores as Record<PresetId, number>,
	};
}
