import type { ScenarioDef } from "../types.js";
import * as crossRunExfil from "./cross-run-credential-exfil.js";
import * as deGetBody from "./data-exfil-get-body.js";
import * as deGetHeader from "./data-exfil-get-header.js";
import * as deHttpPost from "./data-exfil-http-post.js";
import * as deShellCurl from "./data-exfil-shell-curl.js";
import * as dbEscalation from "./db-escalation.js";
import * as egressConvergence from "./egress-convergence.js";
import * as fsSymlinkEscape from "./fs-symlink-parent-escape.js";
import * as fsPathEscape from "./fs-traversal-path-escape.js";
import * as fsSensitive from "./fs-traversal-sensitive.js";
import * as lowEntropyExfil from "./low-entropy-exfil.js";
import * as pathAmbiguity from "./path-ambiguity-bypass.js";
import * as piCmdExec from "./prompt-injection-cmd-exec.js";
import * as piExfil from "./prompt-injection-exfil.js";
import * as piFsWrite from "./prompt-injection-fs-write.js";
import * as remoteMitm from "./remote-decision-mitm.js";
import * as repeatedProbe from "./repeated-probe-quarantine.js";
import * as sharedStoreContam from "./shared-store-contamination.js";
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
	// Data Exfiltration (5)
	def(deHttpPost),
	def(deShellCurl),
	def(deGetHeader),
	def(deGetBody),
	def(remoteMitm),
	// Filesystem Traversal (4)
	def(fsPathEscape),
	def(fsSensitive),
	def(fsSymlinkEscape),
	def(repeatedProbe),
	// Database Escalation (1)
	def(dbEscalation),
	// Taint Chain (2)
	def(tcWebShell),
	def(tcRagFile),
	// Multi-Step Attack Sequences (5)
	def(crossRunExfil),
	def(sharedStoreContam),
	def(egressConvergence),
	def(pathAmbiguity),
	def(lowEntropyExfil),
];
