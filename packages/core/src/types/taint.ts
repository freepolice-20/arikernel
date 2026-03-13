export const TAINT_SOURCES = [
	"web",
	"rag",
	"email",
	"retrieved-doc",
	"model-generated",
	"user-provided",
	"tool-output",
	"derived-sensitive",
	"content-scan",
] as const;

export type TaintSource = (typeof TAINT_SOURCES)[number];

export interface TaintLabel {
	source: TaintSource;
	origin: string;
	confidence: number;
	addedAt: string;
	propagatedFrom?: string;
}
