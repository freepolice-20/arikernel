import { writeFileSync, existsSync } from 'node:fs';

const DEFAULT_POLICY = `name: my-agent-policy
version: "1.0"

rules:
  - id: allow-safe-http
    name: Allow HTTP GET requests
    priority: 100
    match:
      toolClass: http
      action: get
    decision: require-approval
    reason: "HTTP GET requests require approval"

  - id: allow-file-read
    name: Allow file reads
    priority: 110
    match:
      toolClass: file
      action: read
    decision: allow
    reason: "File reads are allowed"

  - id: deny-tainted-shell
    name: Deny shell with untrusted input
    priority: 50
    match:
      toolClass: shell
      taintSources: [web, rag, email]
    decision: deny
    reason: "Shell commands with untrusted input are forbidden"
`;

export function runInit(): void {
	const policyPath = 'arikernel.policy.yaml';

	if (existsSync(policyPath)) {
		console.log(`Policy file already exists: ${policyPath}`);
		return;
	}

	writeFileSync(policyPath, DEFAULT_POLICY, 'utf-8');
	console.log(`Created ${policyPath}`);
	console.log('Edit this file to configure your arikernel policies.');
}
