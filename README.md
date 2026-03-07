# Agent Firewall

A runtime security layer for AI agents. Sits between an LLM agent and its tools, enforcing capability-based permissions, taint-aware execution policies, and tamper-evident audit logging.

**Core thesis:** AI agents should never execute with ambient authority. Every tool call must be explicitly authorized by a short-lived, scope-limited capability token — and every decision must be auditable.

## The Problem

AI agents are being given direct access to tools: HTTP requests, shell commands, file I/O, databases. Most deployments rely on prompt-level instructions ("don't do anything harmful") or static allow/deny lists. Neither is sufficient.

**Prompt filters fail because:**
- Prompt injections bypass them trivially (hidden instructions in web pages, emails, RAG documents)
- They operate on intent, not on actions — and intent is unverifiable in an LLM
- They have no concept of data provenance: content from an untrusted webpage is treated the same as user input

**Static gateways fail because:**
- They make binary allow/deny decisions with no context about where data came from
- They cannot distinguish "agent reads a file for the user" from "agent reads ~/.ssh/id_rsa because a webpage told it to"
- They have no token lifecycle: once access is granted, it persists until manually revoked

**Agent Firewall solves this with four enforced layers:**

1. **Capability tokens** — agents must request and receive a short-lived, usage-limited token before executing any protected action
2. **Taint tracking** — data provenance labels propagate through the tool call chain; untrusted sources block sensitive operations
3. **Policy enforcement** — YAML-defined rules with priority ordering, first-match-wins, deny-by-default
4. **Tamper-evident audit** — every decision is logged in a SHA-256 hash-chained event store

## Quick Start

```bash
# Prerequisites: Node.js >= 20, pnpm >= 9
git clone https://github.com/petermanrique101-sys/Agent-Firewall.git
cd Agent-Firewall

# Install and build
pnpm install
pnpm build

# Run demos
pnpm demo              # Core pipeline: allow, deny, approval, taint, audit replay
pnpm demo:capability   # Capability issuance: taint-aware token granting and denial
pnpm demo:attack       # Prompt injection: 4-stage attack blocked by 4 defense layers
pnpm demo:escalation   # Privilege escalation: narrow token cannot be widened

# Run tests
pnpm test

# Clean build artifacts (safe, keeps node_modules)
pnpm clean

# Full reset (removes node_modules — requires pnpm install after)
pnpm reset
```

## Demo Overview

### `pnpm demo` — Core Pipeline
Exercises the basic intercept flow: HTTP GET allowed, unauthorized host denied, tainted shell command blocked, approval flow, and audit replay with hash chain verification.

### `pnpm demo:capability` — Capability Issuance
Shows dynamic token issuance. An agent requests `http.read` (granted), then requests `database.read` with web-tainted provenance (denied because untrusted content cannot trigger database access). Demonstrates that capability decisions are context-dependent, not static.

### `pnpm demo:attack` — Prompt Injection Simulation
A webpage contains a hidden prompt injection instructing the agent to exfiltrate SSH keys, download a backdoor, and send confirmation to an attacker. All 4 attack steps are blocked by different defense layers (constraint enforcement, principal capability check, taint-aware issuance denial, mandatory token enforcement). The audit trail shows exactly 4 DENY events with full provenance.

### `pnpm demo:escalation` — Capability Escalation
An agent with a narrow HTTP GET token attempts to escalate: POST with a GET-only token (action mismatch), shell exec without any capability (no token), file read outside allowed paths (constraint violation), and reuse of a revoked token (lifecycle enforcement). 1 legitimate action allowed, 4 escalation attempts blocked. 5 audit events total.

## How It Works

```
Agent requests action
        |
        v
  [1] Validate request schema
        |
        v
  [2] Is this a protected action?
       / Yes            \ No
      v                  v
  Token required     (unprotected — rare)
      |
      v
  [3] Validate capability token
      - exists?
      - not expired?
      - not revoked?
      - principal matches?
      - tool class matches?
      - action permitted?
      - constraints satisfied?
      - lease not exhausted?
        |
        v
  [4] Evaluate policy rules
      - taint-source deny rules (priority 10-11)
      - approval-required rules (priority 100-110)
      - allow rules (priority 200-230)
      - implicit deny-all (priority 999)
        |
        v
  [5] Execute or Deny
      |           |
      v           v
   Execute    Throw ToolCallDeniedError
      |           |
      v           v
  [6] Audit log (SHA-256 hash chain)
```

**Capability issuance** (step 0, before the above flow):
1. Agent calls `firewall.requestCapability('http.read', { taintLabels })`
2. Issuer checks: does the principal have base capability for this tool class?
3. Issuer checks: are the requested actions within the allowed set?
4. Issuer checks: does the taint context include untrusted sources for sensitive operations?
5. Issuer checks: do policy rules deny this issuance?
6. If all pass: issue a grant with a 5-minute TTL and 10-call lease

## Project Structure

```
agent-firewall/
├── packages/
│   ├── core/              # Shared types, Zod schemas, error classes, ID generation
│   ├── policy-engine/     # YAML policy loading, rule matching, priority-sorted evaluation
│   ├── taint-tracker/     # Taint label creation, propagation, and querying
│   ├── audit-log/         # SQLite-backed event store with SHA-256 hash chain
│   ├── tool-executors/    # Tool implementations (HTTP, file, shell, database)
│   ├── runtime/           # Main orchestrator: Firewall, Pipeline, CapabilityIssuer, TokenStore
│   └── attack-sim/        # Attack scenario definitions and simulation runner
├── apps/
│   ├── cli/               # Command-line interface (init, policy validate, replay, simulate)
│   └── server/            # HTTP decision server for cross-language integration
├── python/                # Python client package (v1 decision/enforcement adapter)
├── policies/              # YAML policy files (safe-defaults, deny-all, examples)
├── examples/              # Runnable demos (TypeScript and Python)
└── docs/                  # Threat model, roadmap
```

### Package Responsibilities

| Package | What it does |
|---------|-------------|
| `@agent-firewall/core` | Domain types (`ToolCall`, `CapabilityGrant`, `TaintLabel`, `PolicyRule`, etc.), Zod validation schemas, error classes, ULID-based ID generation |
| `@agent-firewall/policy-engine` | Loads YAML policy files, sorts rules by priority, evaluates first-match-wins against tool calls and taint labels |
| `@agent-firewall/taint-tracker` | Attaches provenance labels to data, propagates taint through tool call chains, queries taint state |
| `@agent-firewall/audit-log` | Appends events to SQLite with SHA-256 hash chaining, supports replay and integrity verification |
| `@agent-firewall/tool-executors` | Concrete implementations for HTTP (fetch), file (fs), shell (child_process), database (stub) |
| `@agent-firewall/runtime` | `Firewall` class (main entry point), `Pipeline` (intercept flow), `CapabilityIssuer` (token issuance), `TokenStore` (grant lifecycle) |
| `@agent-firewall/attack-sim` | Predefined attack scenarios (prompt injection, tool misuse, data exfiltration, privilege escalation) |

## Writing Policies

Policies are YAML files with priority-sorted rules. Lower priority number = higher precedence. First match wins.

```yaml
name: my-policy
version: "1.0"

rules:
  - id: deny-tainted-shell
    name: Block shell commands from untrusted input
    priority: 10
    match:
      toolClass: shell
      taintSources: [web, rag, email]
    decision: deny
    reason: "Shell execution with untrusted input is forbidden"

  - id: allow-http-get
    name: Allow read-only HTTP
    priority: 200
    match:
      toolClass: http
      action: get
    decision: allow
    reason: "HTTP GET is read-only"
```

Built-in deny-all rule at priority 999 ensures anything not explicitly allowed is denied.

## Audit Replay

Every demo writes a tamper-evident audit log. Use the CLI to replay and inspect any run.

```bash
# Replay the latest run in an audit database
pnpm cli replay --db ./demo-attack-audit.db --latest

# Replay a specific run by ID
pnpm cli replay --db ./demo-escalation-audit.db <run-id>

# Verbose mode: show parameters, matched rule, and hash per event
pnpm cli replay --db ./demo-attack-audit.db --latest --verbose
```

**Example output (compact):**

```
────────────────────────────────────────────────────────
 Audit Replay
────────────────────────────────────────────────────────
  Run ID:    01JQWX...
  Principal: attack-demo-agent
  Started:   2026-03-06T12:00:00Z
────────────────────────────────────────────────────────

  #0 DENY  http.post  [no token]  -
     Reason: Capability token required for protected action
     Taint:  web:evil-page.com

  #1 DENY  shell.exec [no token]  -
     Reason: Capability token required for protected action
     Taint:  web:evil-page.com

  #2 DENY  http.post  [no token]  -
     Reason: Capability token required for protected action
     Taint:  web:evil-page.com

  #3 DENY  file.read  [no token]  -
     Reason: Capability token required for protected action
     Taint:  web:evil-page.com

────────────────────────────────────────────────────────
 Summary

  Total events:       4
  Allowed:            0
  Denied:             4

  Hash chain:         VALID
────────────────────────────────────────────────────────
```

## Python Integration (v1)

The v1 Python adapter is a **decision/enforcement API layer** over the TypeScript core. The server decides allow or deny and writes every decision to the audit log. Actual tool execution still happens in your Python code after receiving an allow verdict.

This is a first integration step — not full runtime mediation. A future version may add server-side execution.

### Setup

```bash
# Start the decision server (from repo root)
pnpm build && pnpm server

# Install the Python client (in another terminal)
pip install -e python/
```

### Usage

```python
from agent_firewall import FirewallClient, ToolCallDenied

with FirewallClient(
    url="http://localhost:9099",
    principal="my-agent",
    capabilities=[
        {"toolClass": "http", "actions": ["get"],
         "constraints": {"allowedHosts": ["api.github.com"]}},
    ],
) as fw:
    grant = fw.request_capability("http.read")
    if grant.granted:
        result = fw.execute("http", "get",
            {"url": "https://api.github.com/repos/example"},
            grant_id=grant.grant_id)
        # result.verdict == "allow" -> now execute your actual HTTP call
```

### Run the demo and tests

```bash
python examples/python-demo.py    # Interactive demo with 4 phases
python -m pytest python/tests/ -v # Integration tests (starts server automatically)
```

See [python/README.md](python/README.md) for full API documentation.

## Current Status

This is an MVP / proof-of-concept. The core enforcement model works end-to-end:
- Capability token issuance and validation
- Taint-aware denial of sensitive operations
- Constraint enforcement (allowed hosts, paths, commands, databases)
- Token lifecycle (expiry, usage limits, revocation)
- Hash-chained audit logging with replay

See [docs/threat-model.md](docs/threat-model.md) for what this does and does not protect against, and [docs/roadmap.md](docs/roadmap.md) for planned work.

## License

Apache-2.0
