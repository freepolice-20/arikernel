# Ari Kernel

**A Runtime Security Reference Monitor for AI Agents**

Ari Kernel enforces security at the execution boundary between AI agents and their tools. It intercepts every tool call, evaluates it against capability tokens, data provenance, policy rules, and behavioral patterns, then allows, denies, or quarantines the session before anything executes.

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
│  ├─ tamper-evident audit log      │
│  └─ deterministic replay          │
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

Ari Kernel intercepts every tool call an AI agent makes and enforces security through six layers. The agent cannot bypass enforcement because all tool calls are routed through the kernel before anything executes.

**Capability tokens** — scoped, time-limited (5 min), usage-limited (10 calls). No ambient authority. A token for `file.read` does not grant `file.write`.

**Taint tracking** — data carries provenance labels (`web`, `rag`, `email`) that propagate through tool chains. Untrusted provenance blocks sensitive operations automatically.

**Behavioral sequence detection** — a sliding window (last 20 events) tracks multi-step patterns across the session. Six built-in rules detect prompt-injection-to-exfiltration sequences, privilege escalation, tainted database writes, and secret access followed by egress.

**Run-level quarantine** — when a behavioral rule matches or denial counters exceed a threshold, the session enters restricted mode. Only read-only actions pass for the remainder of the run. Immediate, irrecoverable containment.

**Tamper-evident audit** — every decision is logged in a SHA-256 hash-chained event store. Quarantine events, trigger metadata, and matched patterns are first-class audit records.

**Deterministic replay** — record any run as a JSON trace, then replay it through a fresh kernel to verify every security decision is reproducible. Swap policies for what-if analysis. No side effects are re-executed.

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
- Six built-in rules covering taint-to-probe, escalation, read-then-egress, tainted database writes, tainted shell commands, and secret access followed by egress
- Fires on first match — no threshold delay

### Containment
- Run-level quarantine locks the session to read-only operations
- Triggered by behavioral rules or denial count thresholds
- Irrecoverable within the run — compromised sessions are isolated, not rehabilitated

### Forensics
- SHA-256 hash-chained audit log with tamper detection
- Deterministic replay — record a run, replay it through a fresh kernel, verify every decision matches
- What-if analysis — replay with different policies to see how decisions change
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

| Mode | Description |
|------|-------------|
| **Embedded (library)** | `createKernel()` integrated into the agent process. Zero network overhead. |
| **Sidecar (HTTP proxy)** | Standalone process on port 8787. Language-agnostic — any HTTP client works. Process-level trust boundary. |

Embedded mode is the primary deployment path — native runtimes exist for both TypeScript/JavaScript and Python. Sidecar mode provides process-level isolation and works with any language via HTTP.

---

## Quick Start

```bash
git clone https://github.com/petermanrique101-sys/AriKernel.git
cd AriKernel
pnpm install && pnpm build

# Run demos
pnpm demo:real-agent                                      # full agent demo (requires OPENAI_API_KEY)
pnpm demo:behavioral                                      # behavioral quarantine demo
pnpm demo:sidecar                                         # sidecar proxy mode

# Deterministic replay
pnpm demo:replay                                           # records trace + replays it
pnpm ari replay-trace demo-trace.json --verbose            # replay via CLI

# Replay audit trail
pnpm ari replay --latest --verbose --db ./demo-audit.db
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
| OpenAI Agents SDK | `protectAgentTools()` |
| LangChain / LangGraph | `LangChainAdapter` |
| LlamaIndex TS | `LlamaIndexAdapter` |
| CrewAI | `CrewAIAdapter` |
| Vercel AI SDK | `protectVercelTools()` |
| MCP (Model Context Protocol) | `protectMCPTools()` |
| Microsoft AutoGen (Python) | `protect_autogen_tool()` / `AutoGenToolWrapper` |
| AutoGPT (Python) | `protect_autogpt_command()` / `AutoGPTCommandWrapper` |
| OpenClaw (experimental) | `OpenClawAdapter` |
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

Six built-in rules detect suspicious multi-step patterns:

| Rule | Pattern | Catches |
|------|---------|---------|
| `web_taint_sensitive_probe` | Untrusted taint → sensitive file read or shell exec | Prompt injection → credential theft |
| `denied_capability_then_escalation` | Denied capability → request for riskier capability | Automated privilege escalation |
| `sensitive_read_then_egress` | Sensitive file read → outbound POST/PUT/PATCH | Data exfiltration sequences |
| `tainted_database_write` | Untrusted taint → database write/exec/mutate | Tainted SQL injection |
| `tainted_shell_with_data` | Untrusted taint → shell exec with long command string | Data piping via shell args |
| `secret_access_then_any_egress` | Secret/credential resource access → any egress | Credential theft sequences |

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
| `arikernel replay-trace <file>` | Replay a JSON trace file through the kernel |
| `arikernel sidecar` | Start sidecar proxy on port 8787 |
| `arikernel init` | Interactive project setup |
| `arikernel policy <file>` | Validate a policy YAML file |

All forensic commands default to `./arikernel-audit.db`. Override with `--db <path>`.

---

## Demos

Every command below works from the repo root after `pnpm install && pnpm build`:

```bash
# Real agent demo (requires OPENAI_API_KEY)
pnpm demo:real-agent          # LLM agent vs. prompt injection, quarantine + replay

# Core demos
pnpm demo:behavioral          # behavioral quarantine (web taint → sensitive read)
pnpm demo:attack              # 4-stage prompt injection attack, all blocked
pnpm demo:run-state           # threshold-based quarantine
pnpm demo:replay              # deterministic attack replay

# Deterministic replay via CLI
pnpm ari replay-trace examples/demo-real-agent/trace.json --verbose

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
pnpm test:live                # live integration tests (requires OPENAI_API_KEY)
```

---

## Sidecar Mode

Ari Kernel can run as a standalone HTTP proxy that enforces policy before any tool executes. The agent sends `POST /execute` requests; the sidecar evaluates capability tokens, taint, policy rules, and behavioral patterns, then returns the result or a denial.

```bash
arikernel sidecar --policy ./arikernel.policy.yaml --port 8787
```

The sidecar provides process-level isolation: the agent cannot access the policy engine, run-state, or audit log. Each principal gets an independent kernel instance with its own quarantine state.

See [Sidecar Mode](docs/sidecar-mode.md) for the full API reference.

---

## Deterministic Replay

Record any run as a JSON trace, then replay it through a fresh kernel to verify every security decision is reproducible.

```bash
# Record a trace during a demo
pnpm demo:replay

# Replay it
pnpm ari replay-trace demo-trace.json --verbose

# What-if: replay with a different preset
pnpm ari replay-trace demo-trace.json --preset workspace-assistant
```

Replay verifies security decisions only — external side effects (HTTP requests, file I/O) are stubbed. This makes replay safe, fast, and deterministic.

See [Deterministic Replay](docs/replay.md) for details.

---

## Current Limitations

- **Early-stage project** — core enforcement model is stable, but the API surface may evolve
- **In-memory token store** — capability tokens are not persisted across process restarts
- **Stub executors** — database and retrieval executors validate and audit calls but do not execute real queries
- **Adapter coverage** — integrations are thin wrappers; deep framework plugins are not yet available
- **Replay is decision-only** — deterministic replay verifies security decisions, not external side effects. HTTP requests, file I/O, and shell commands are stubbed during replay.

---

## Project Structure

```
AriKernel/
├── packages/
│   ├── core/                     # Types, schemas, errors, presets
│   ├── policy-engine/            # YAML policy loading, rule evaluation
│   ├── taint-tracker/            # Taint label attach, propagate, query
│   ├── audit-log/                # SQLite store, SHA-256 hash chain, replay
│   ├── tool-executors/           # HTTP, file, shell, database, retrieval executors
│   ├── runtime/                  # Kernel, pipeline, capability issuer, behavioral rules
│   ├── adapters/                 # Framework adapters (OpenAI, LangChain, CrewAI, Vercel AI, etc.)
│   ├── mcp-adapter/              # MCP tool integration
│   ├── sidecar/                  # HTTP proxy enforcement server
│   ├── attack-sim/               # Attack scenario runner
│   └── benchmarks-agentdojo/     # AgentDojo-style attack benchmark harness
├── apps/
│   └── cli/                      # CLI (simulate, trace, replay, replay-trace, sidecar, init, policy)
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
- [Deterministic Replay](docs/replay.md) — record, replay, and verify security decisions
- [Sidecar Mode](docs/sidecar-mode.md) — language-agnostic HTTP enforcement proxy
- [Execution Hardening](docs/execution-hardening.md) — OS and container-level security recommendations

---

## License

Apache-2.0
