import type { ScenarioDef } from "../types.js";
import * as deHttpPost from "./data-exfil-http-post.js";
import * as deShellCurl from "./data-exfil-shell-curl.js";
import * as dbEscalation from "./db-escalation.js";
import * as fsPathEscape from "./fs-traversal-path-escape.js";
import * as fsSensitive from "./fs-traversal-sensitive.js";
import * as piCmdExec from "./prompt-injection-cmd-exec.js";
import * as piExfil from "./prompt-injection-exfil.js";
import * as piFsWrite from "./prompt-injection-fs-write.js";
import * as repeatedProbe from "./repeated-probe-quarantine.js";
import * as tcRagFile from "./taint-chain-rag-file.js";
import * as tcWebShell from "./taint-chain-web-shell.js";
import * as teHttp from "./tool-escalation-http.js";
import * as teShell from "./tool-escalation-shell.js";

function def(mod: {
	ID: string;
	NAME: string;
	CATEGORY: ScenarioDef["category"];
	DESCRIPTION: string;
	run: ScenarioDef["run"];
}): ScenarioDef {
	return {
		id: mod.ID,
		name: mod.NAME,
		category: mod.CATEGORY,
		description: mod.DESCRIPTION,
		run: mod.run,
	};
}

export const SCENARIOS: ScenarioDef[] = [
	// Prompt Injection (3)
	def(piExfil),
	def(piFsWrite),
	def(piCmdExec),
	// Tool Escalation (2)
	def(teShell),
	def(teHttp),
	// Data Exfiltration (2)
	def(deHttpPost),
	def(deShellCurl),
	// Filesystem Traversal (3)
	def(fsPathEscape),
	def(fsSensitive),
	def(repeatedProbe),
	// Database Escalation (1)
	def(dbEscalation),
	// Taint Chain (2)
	def(tcWebShell),
	def(tcRagFile),
];
