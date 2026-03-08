# Ari Kernel

**The Runtime Security Layer for AI Agents**

> Don't give AI agents root access to the internet.

Ari Kernel introduces runtime enforcement for AI agents by placing an **Agent Runtime Inspector (ARI)** between agents and external tools. It intercepts every tool call at the execution boundary — where decisions become real actions — and enforces least-privilege security before anything executes.

```
        Agent / LLM Runtime
                │
                │ tool call
                ▼
┌───────────────────────────────────┐
│  ARI — Agent Runtime Inspector    │
│  Enforcement Boundary             │
│                                   │
│  ┌─ capability token enforcement  │
│  ├─ taint / provenance tracking   │
│  ├─ policy engine                 │
│  ├─ behavioral sequence detection │
│  ├─ run-level quarantine          │
│  └─ tamper-evident audit log      │
│                                   │
│  allow / deny / quarantine        │
└───────────────┬───────────────────┘
                │
                ▼
  Protected Tools / Resources
  files │ http │ shell │ db │ retrieval │ mcp
```

---

## The Problem

AI agents operate with ambient authority over tools. When an agent can call an HTTP endpoint, it can call *any* endpoint. When it has file access, it can read *any* file the process can reach. There is no permission boundary between "the model decided to call a function" and "the function executed."

This creates a class of attacks that prompt-level defenses cannot stop:

- **Prompt injection** — attacker-controlled content instructs the agent to read secrets or execute commands
- **Data exfiltration** — the agent reads credentials, then POSTs them to an external server
- **Privilege escalation** — a denied capability leads the agent to probe for riskier alternatives
- **Unsafe tool execution** — shell commands or file writes with untrusted input

Prompt filters, system prompts, and output guardrails operate on text. They have no enforcement mechanism — they cannot prevent a tool call from executing. Ari Kernel enforces security at the execution boundary, where tool calls become real actions.

---

## What Ari Kernel Does

Ari Kernel intercepts every tool call an AI agent makes and enforces security through five layers. The agent cannot bypass enforcement because all tool calls are routed through the kernel before anything executes.

**Capability tokens** — scoped, time-limited (5 min), usage-limited (10 calls). No ambient authority. A token for `file.read` does not grant `file.write`.

**Taint tracking** — data carries provenance labels (`web`, `rag`, `email`) that propagate through tool chains. Untrusted provenance blocks sensitive operations automatically.

**Behavioral sequence detection** — a sliding window (last 20 events) tracks multi-step patterns across the session. Three built-in rules detect prompt-injection-to-exfiltration sequences.

**Run-level quarantine** — when a behavioral rule matches or denial counters exceed a threshold, the session enters restricted mode. Only read-only actions pass for the remainder of the run. Immediate, irrecoverable containment.

**Tamper-evident audit** — every decision is logged in a SHA-256 hash-chained event store. Quarantine events, trigger metadata, and matched patterns are first-class audit records.

---

## Example: Prompt Injection Attack

```
1. Agent fetches webpage                    → ALLOWED (HTTP GET, tagged with web taint)
2. Page contains hidden prompt injection
3. Injected instruction: "read ~/.ssh/id_rsa"
4. Agent attempts sensitive file read       → BLOCKED
   ├─ behavioral rule web_taint_sensitive_probe fires
   └─ run enters QUARANTINE
5. Agent attempts POST to attacker.com      → BLOCKED (quarantine: all writes denied)
6. Full sequence recorded in audit log      → arikernel replay --latest
```

Without runtime enforcement, all steps execute and the SSH key is exfiltrated. With Ari Kernel, the behavioral rule detects the sequence — web taint followed by a sensitive read — and quarantines the run. The agent cannot retry, escalate, or pivot.

---

## Key Features

### Runtime Enforcement
- Capability token gating for every protected tool call
- Tool execution mediation at the call boundary
- Policy engine with priority-sorted, first-match-wins YAML rules
- Deny-by-default — anything not explicitly allowed is blocked

### Behavioral Detection
- Cross-step attack pattern detection via sliding event window
- Three built-in rules: taint-to-probe, escalation, read-then-egress
- Fires on first match — no threshold delay

### Containment
- Run-level quarantine locks the session to read-only operations
- Triggered by behavioral rules or denial count thresholds
- Irrecoverable within the run — compromised sessions are isolated, not rehabilitated

### Forensics
- SHA-256 hash-chained audit log with tamper detection
- CLI tools for trace, replay, and step-by-step session review
- Quarantine events include trigger rule, matched pattern, and counters snapshot

---

## How Ari Kernel Compares

| Tool | Layer | Runtime Enforcement | Taint Tracking | Behavioral Quarantine | Audit Chain |
|------|-------|--------------------|-----------------|-----------------------|-------------|
| **Ari Kernel** | Execution boundary | Yes — deny/allow/quarantine | Yes — auto-taint from HTTP/RAG | Yes — sequence detection + run lockdown | SHA-256 hash chain |
| NeMo Guardrails | Prompt/response | Advisory (flow control) | No | No | No |
| Llama Guard | Model output | Advisory (flag/block output) | No | No | No |
| LangChain Guardrails | Prompt/response | Advisory (raise exception) | No | No | No |
| Lakera Guard | Prompt/response | Advisory (detect/flag) | No | No | No |

Most tools validate or monitor. Ari Kernel **enforces** — it sits in the execution path and blocks tool calls that violate policy, regardless of what the model decided.

---

## Deployment Modes

| Mode | Status | Description |
|------|--------|-------------|
| **Embedded (library)** | Stable | `createKernel()` integrated into the agent process. Zero network overhead. |
| **Sidecar (HTTP proxy)** | Experimental | Standalone process on port 8787. Language-agnostic — any HTTP client works. |

Embedded mode is the primary deployment path. The sidecar is functional and tested but considered experimental for production use.

---

## Quick Start

```bash
git clone https://github.com/petermanrique101-sys/AriKernel.git
cd AriKernel
pnpm install && pnpm build

pnpm demo:behavioral                                      # behavioral quarantine demo
pnpm ari replay --latest --verbose --db ./demo-audit.db    # replay the audit trail
```

### TypeScript

```typescript
import { createKernel } from "@arikernel/runtime"
import { protectTools } from "@arikernel/adapters"

// Zero-config: safe defaults, no policy file needed
const tools = protectTools({
  web_search: { toolClass: "http", action: "get" },
  read_file:  { toolClass: "file", action: "read" },
})

await tools.web_search({ url: "https://example.com" })  // ALLOWED
```

### Python

```bash
pip install -e python/
```

```python
from arikernel import create_kernel, protect_tool

kernel = create_kernel(preset="safe-research", audit_log="./audit.db")

@protect_tool("file.read", kernel=kernel)
def read_file(path: str) -> str:
    return open(path).read()

@protect_tool("http.read", kernel=kernel)
def fetch_url(url: str) -> str:
    return httpx.get(url).text

read_file(path="./data/report.csv")    # ALLOWED
read_file(path="/etc/shadow")          # DENIED (path constraint)
```

Both runtimes produce compatible audit logs — same SQLite schema, same hash chain format:

```bash
pnpm ari trace --latest --db ./audit.db
pnpm ari replay --latest --verbose --db ./audit.db
```

---

## Supported Integrations

| Integration | Adapter |
|-------------|---------|
| Generic JS/TS wrapper | `protectTools()` |
| OpenAI-style tool calling | `protectOpenAITools()` |
| LangChain / LangGraph | `LangChainAdapter` |
| CrewAI | `CrewAIAdapter` |
| Vercel AI SDK | `protectVercelTools()` |
| MCP (Model Context Protocol) | `protectMCPTools()` |
| Custom agent loop | Model-agnostic — works with any provider |

Ari Kernel is model-agnostic. It protects tool execution, not the model. Works with OpenAI, Claude, Gemini, or any provider.

---

## Security Presets

Built-in profiles for common agent types:

| Preset | Use Case | HTTP | Files | Shell | Database |
|--------|----------|------|-------|-------|----------|
| `safe-research` | Web research, summarization | GET only | Read `./data/**`, `./docs/**` | Blocked | — |
| `rag-reader` | Document retrieval, RAG | — | Read `./docs/**`, `./data/**` | Blocked | Query only |
| `workspace-assistant` | Coding assistants | GET only | Read + Write `./**` | Approval-gated | — |
| `automation-agent` | Workflow automation | GET + POST | Blocked | Blocked | Query + Write |

Zero-config mode (no preset) applies safe defaults: HTTP GET allowed, file reads restricted, everything else blocked.

---

## Behavioral Sequence Rules

Three built-in rules detect suspicious multi-step patterns:

| Rule | Pattern | Catches |
|------|---------|---------|
| `web_taint_sensitive_probe` | Untrusted taint → sensitive file read or shell exec | Prompt injection → credential theft |
| `denied_capability_then_escalation` | Denied capability → request for riskier capability | Automated privilege escalation |
| `sensitive_read_then_egress` | Sensitive file read → outbound POST/PUT/PATCH | Data exfiltration sequences |

Rules operate on a sliding window (last 20 events) and quarantine the run immediately on match.

---

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

---

## CLI

From the repo root, use `pnpm ari <command>`. If installed globally (`npm install -g @arikernel/cli`), use `arikernel <command>`.

| Command | Description |
|---------|-------------|
| `arikernel simulate [type]` | Run attack simulations (prompt-injection, data-exfiltration, tool-escalation) |
| `arikernel trace [runId]` | Display security execution trace |
| `arikernel replay [runId]` | Replay a recorded session step by step |
| `arikernel init` | Interactive project setup |
| `arikernel policy <file>` | Validate a policy YAML file |

All forensic commands default to `./arikernel-audit.db`. Override with `--db <path>`.

---

## Demos

Every command below works from the repo root after `pnpm install && pnpm build`:

```bash
# Core demos
pnpm demo:behavioral          # behavioral quarantine (web taint → sensitive read)
pnpm demo:attack              # 4-stage prompt injection attack, all blocked
pnpm demo:run-state           # threshold-based quarantine

# Framework integrations
pnpm demo:langchain           # LangChain integration
pnpm demo:openai              # OpenAI-style tool calling
pnpm demo:crewai              # CrewAI tool protection
pnpm demo:mcp                 # MCP tool protection
pnpm demo:sidecar             # sidecar proxy mode

# Python
pnpm demo:python              # basic agent with protect_tool decorator
pnpm demo:python:quarantine   # behavioral quarantine in Python

# Tests
pnpm test                     # all TypeScript tests
```

---

## Current Limitations

- **Early-stage project** — core enforcement model is stable, but the API surface may evolve
- **In-memory token store** — capability tokens are not persisted across process restarts
- **Stub executors** — database and retrieval executors validate and audit calls but do not execute real queries
- **Sidecar is experimental** — functional and tested, not yet hardened for production
- **Adapter coverage** — integrations are thin wrappers; deep framework plugins are not yet available

---

## Project Structure

```
AriKernel/
├── packages/
│   ├── core/                     # Types, schemas, errors, presets
│   ├── policy-engine/            # YAML policy loading, rule evaluation
│   ├── taint-tracker/            # Taint label attach, propagate, query
│   ├── audit-log/                # SQLite store, SHA-256 hash chain, replay
│   ├── tool-executors/           # HTTP, file, shell, database executors
│   ├── runtime/                  # Kernel, pipeline, capability issuer, behavioral rules
│   ├── adapters/                 # Framework adapters (OpenAI, LangChain, CrewAI, Vercel AI)
│   ├── mcp-adapter/              # MCP tool integration
│   ├── sidecar/                  # HTTP proxy enforcement server
│   ├── attack-sim/               # Attack scenario runner
│   └── benchmarks-agentdojo/     # AgentDojo-style attack benchmark harness
├── apps/
│   └── cli/                      # CLI (simulate, trace, replay, init, policy)
├── python/                       # Native Python runtime
├── policies/                     # YAML policy files
├── examples/                     # Runnable demos
└── docs/                         # Design docs, threat model, benchmarks
```

---

## Documentation

- [Security Model](docs/security-model.md) — capability tokens, taint tracking, behavioral rules, quarantine
- [Architecture](ARCHITECTURE.md) — enforcement pipeline, run-state model, deployment modes
- [Agent Reference Monitor](docs/agent-reference-monitor.md) — the reference monitor concept applied to AI agents
- [Threat Model](docs/threat-model.md) — what Ari Kernel mitigates and what it doesn't
- [Benchmarks](docs/benchmarks.md) — 4 attack stories with unguarded vs. protected outcomes
- [AgentDojo Benchmark](docs/benchmark-agentdojo.md) — 5-scenario reproducible attack harness
- [MCP Integration](docs/mcp-integration.md) — `protectMCPTools()` API, auto-taint rules, policy examples
- [Sidecar Mode](docs/sidecar-mode.md) — language-agnostic HTTP enforcement proxy

---

## License

Apache-2.0
