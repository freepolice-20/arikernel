# Ari Kernel

Runtime enforcement layer for AI agent tools. Sits between an agent and its tools, enforcing least-privilege capability tokens, taint-aware policies, behavioral quarantine, and tamper-evident forensics.

```
Agent chooses tool
       │
       ▼
┌──────────────────────────────┐
│        Ari Kernel            │
│                              │
│  capability token check      │
│  taint / provenance check    │
│  behavioral sequence check   │
│  policy evaluation           │
│                              │
│  → allow / deny / quarantine │
│  → SHA-256 audit log         │
└──────────────────────────────┘
       │
       ▼
Tool executes (or is blocked)
```

## What It Does

Ari Kernel intercepts every tool call an AI agent makes — HTTP requests, file reads, shell commands, database queries — and enforces security at the execution boundary. The agent cannot bypass enforcement because tool calls are routed through the kernel before anything executes.

Five enforcement layers:

1. **Capability tokens** — scoped, time-limited (5 min), usage-limited (10 calls). No ambient authority.
2. **Taint tracking** — data carries provenance labels (`web`, `rag`, `email`) that propagate through tool chains. Untrusted provenance blocks sensitive operations.
3. **Behavioral sequence detection** — a sliding window tracks multi-step patterns across the session. Three built-in rules detect prompt-injection-to-exfiltration sequences.
4. **Run-level quarantine** — when a behavioral rule matches or denial counters exceed a threshold, the session enters restricted mode. Only read-only actions pass for the remainder of the run.
5. **Tamper-evident audit** — every decision is logged in a SHA-256 hash-chained event store. Quarantine events, trigger metadata, and matched patterns are first-class audit records.

## 60-Second Quick Start

### TypeScript

```bash
git clone https://github.com/petermanrique101-sys/AriKernel.git
cd AriKernel
pnpm install && pnpm build

pnpm demo:behavioral                                      # run behavioral quarantine demo
pnpm ari replay --latest --verbose --db ./demo-audit.db    # replay the audit trail
```

### Python

```bash
pip install -e python/
python examples/python-basic-agent.py
pnpm ari trace --latest --db python-agent-audit.db
```

## TypeScript Usage

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

With a named preset:

```typescript
const kernel = createKernel({ preset: "safe-research" })

const tools = protectTools({
  web_search: { toolClass: "http", action: "get" },
  read_file:  { toolClass: "file", action: "read" },
}, { kernel })
```

## Python Usage

The Python runtime runs enforcement locally — no TypeScript server required. Same security model, same audit format.

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
fetch_url(url="https://example.com")   # ALLOWED
```

Python audit logs are compatible with the TypeScript CLI — same SQLite schema, same hash chain format:

```bash
pnpm ari trace --latest --db ./audit.db
pnpm ari replay --latest --verbose --db ./audit.db
```

## Supported Runtimes and Integrations

| Category | Item | Status | Notes |
|----------|------|--------|-------|
| **Runtime** | TypeScript / JavaScript | Native | In-process enforcement, zero-config or preset-based |
| **Runtime** | Python | Native | In-process enforcement, zero required dependencies |
| **Integration** | Generic JS/TS wrapper | Supported | `protectTools()` — works with any agent loop |
| **Integration** | OpenAI-style tool calling | Supported | `protectOpenAITools()` adapter |
| **Integration** | LangChain / LangGraph | Supported | `LangChainAdapter` wrapper |
| **Integration** | CrewAI | Supported | `CrewAIAdapter` wrapper |
| **Integration** | Custom agent loop | Supported | Model-agnostic — works with any provider |
| **Integration** | Vercel AI SDK | Supported | `protectVercelTools()` adapter |
| **Integration** | MCP (Model Context Protocol) | Supported | `protectMCPTools()` — auto-taint from tool arguments |
| **Deployment** | Sidecar / proxy mode | Supported | `arikernel sidecar` — language-agnostic HTTP enforcement proxy |

Ari Kernel is model-agnostic. It protects tool execution, not the model. Works with OpenAI, Claude, Gemini, or any provider — tool calls eventually become function calls, and Ari Kernel intercepts that boundary.

## Security Presets

Built-in profiles for common agent types:

| Preset | Use Case | HTTP | Files | Shell | Database |
|--------|----------|------|-------|-------|----------|
| `safe-research` | Web research, summarization | GET only | Read `./data/**`, `./docs/**` | Blocked | — |
| `rag-reader` | Document retrieval, RAG | — | Read `./docs/**`, `./data/**` | Blocked | Query only |
| `workspace-assistant` | Coding assistants | GET only | Read + Write `./**` | Approval-gated | — |
| `automation-agent` | Workflow automation | GET + POST | Blocked | Blocked | Query + Write |

Zero-config mode (no preset specified) applies safe defaults: HTTP GET allowed, file reads restricted to `./data/**`, `./docs/**`, `./workspace/**`, everything else blocked.

## AutoScope

AutoScope maps task descriptions to the least-privilege preset automatically:

```typescript
const kernel = createKernel({ autoScope: true })

kernel.selectScope("summarize this webpage")        // → safe-research
kernel.selectScope("analyze this CSV file")          // → rag-reader
kernel.selectScope("refactor the code in this repo") // → workspace-assistant
```

AutoScope is deterministic (keyword-based, no LLM). Falls back to `safe-research` when confidence is low. Optional — you can always use a named preset or zero-config defaults.

## Behavioral Sequence Rules

Three built-in rules detect suspicious multi-step patterns:

| Rule | Pattern | Catches |
|------|---------|---------|
| `web_taint_sensitive_probe` | Untrusted taint → sensitive file read or shell exec | Prompt injection → credential theft |
| `denied_capability_then_escalation` | Denied capability → request for riskier capability | Automated privilege escalation |
| `sensitive_read_then_egress` | Sensitive file read → outbound POST/PUT/PATCH | Data exfiltration sequences |

These rules operate on a sliding window (last 20 events) and quarantine the run immediately on match.

## CLI

From the repo root, use `pnpm ari <command>`. If installed globally (`npm install -g @arikernel/cli`), use `arikernel <command>` directly.

| Command | Shortcut | Description |
|---------|----------|-------------|
| `pnpm ari simulate [type]` | `pnpm ari:simulate` | Run attack simulations |
| `pnpm ari trace [runId]` | `pnpm ari:trace` | Display security execution trace |
| `pnpm ari replay [runId]` | `pnpm ari:replay` | Replay a recorded session step by step |
| `pnpm ari init` | `pnpm ari:init` | Interactive setup |
| `pnpm ari policy <file>` | — | Validate a policy YAML file |

All forensic commands default to `./arikernel-audit.db`. Override with `--db <path>`.

### Attack Simulation

```bash
pnpm ari simulate prompt-injection
pnpm ari simulate data-exfiltration
pnpm ari simulate tool-escalation
pnpm ari:simulate                      # run all scenarios
```

### Trace and Replay

```bash
pnpm ari:trace                         # latest run
pnpm ari:replay                        # latest run, verbose
pnpm ari:replay:step                   # step-by-step with delay
```

## Verified Demo Commands

Every command below has been tested and works from the repo root after `pnpm install && pnpm build`:

```bash
# TypeScript demos
pnpm demo:behavioral          # behavioral quarantine (web taint → sensitive read)
pnpm demo:attack              # 4-stage prompt injection attack, all blocked
pnpm demo:run-state           # threshold-based quarantine
pnpm demo:langchain           # LangChain integration
pnpm demo:generic             # generic JS/TS wrapper
pnpm demo:openai              # OpenAI-style tool calling
pnpm demo:crewai              # CrewAI tool protection
pnpm demo:custom              # custom model-agnostic agent loop
pnpm demo:capability          # capability issuance and taint
pnpm demo:escalation          # privilege escalation blocked

# Python demos
pnpm demo:python              # basic agent with protect_tool decorator
pnpm demo:python:openai       # simulated OpenAI agent loop
pnpm demo:python:quarantine   # behavioral quarantine in Python

# Forensics
pnpm ari replay --latest --verbose --db ./demo-audit.db
pnpm ari trace --latest --db python-quarantine-audit.db
pnpm ari replay --latest --verbose --db python-quarantine-audit.db

# Tests
pnpm test                     # all TypeScript tests
cd python && python -m pytest tests/ -v    # all Python tests
```

## How It Works

```
Agent requests action
        │
        ▼
  [1] Track run-state signals
      - taint observed? → push to event window
      - sensitive file? → push to event window
      - egress attempt? → push to event window
      - behavioral rule match? → quarantine
        │
        ▼
  [2] Validate capability token
      - exists, not expired, not revoked?
      - principal, tool class, action match?
      - constraints satisfied?
      - lease not exhausted?
        │
        ▼
  [3] Evaluate policy rules (priority-sorted, first-match-wins)
        │
        ▼
  [4] Enforce: ALLOW / DENY / REQUIRE-APPROVAL
        │
        ▼
  [5] Execute tool, propagate taint
        │
        ▼
  [6] Audit log (SHA-256 hash chain)
```

**Security model:** Ari Kernel protects tools at the execution boundary. It does not filter prompts or read the model's intent. AutoScope helps translate task descriptions into least-privilege defaults, but enforcement always happens at the tool call layer. The model cannot bypass the enforcement pipeline.

**Deployment mode:** Ari Kernel currently runs in **embedded mode** — the kernel is a library inside the agent process. The agent framework routes tool calls through `createKernel()`, and the LLM has no mechanism to bypass enforcement. For mandatory enforcement with process isolation, a proxy/sidecar mode is on the roadmap.

## Writing Policies

Policies are YAML files with priority-sorted rules. Lower priority = higher precedence. First match wins.

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

## Current Limitations

- **Early-stage project** — the core enforcement model is stable, but the API surface may evolve
- **Embedded mode only** — enforcement runs in-process; proxy/sidecar mode for mandatory process isolation is on the roadmap
- **In-memory token store** — capability tokens are not persisted across process restarts
- **Advisory taint labels** — taint tracking relies on the framework correctly labeling data sources
- **AutoScope is heuristic** — keyword-based classification, not semantic understanding
- **Adapter coverage** — integrations are thin wrappers; deep framework plugins are not yet available

## Project Structure

```
AriKernel/
├── packages/
│   ├── core/              # Types, schemas, errors, presets
│   ├── policy-engine/     # YAML policy loading, rule evaluation
│   ├── taint-tracker/     # Taint label attach, propagate, query
│   ├── audit-log/         # SQLite store, SHA-256 hash chain, replay
│   ├── tool-executors/    # HTTP, file, shell, database executors
│   ├── runtime/           # Kernel, Pipeline, CapabilityIssuer, behavioral rules, AutoScope
│   ├── attack-sim/        # Attack scenario runner
│   ├── adapters/          # Framework adapters (OpenAI, LangChain, CrewAI, Vercel AI)
│   ├── mcp-adapter/       # MCP tool integration via protectMCPTools()
│   ├── sidecar/           # HTTP proxy enforcement server (port 8787)
│   └── benchmarks-agentdojo/ # AgentDojo-style attack benchmark harness
├── apps/
│   ├── cli/               # CLI (simulate, trace, replay, init, policy)
│   └── server/            # HTTP decision server (legacy cross-language mode)
├── python/                # Native Python runtime
│   └── arikernel/runtime/ # Policy engine, taint tracking, behavioral rules, audit logging
├── arikernel-policy.json  # Shared policy spec (consumed by both runtimes)
├── policies/              # YAML policy files
├── examples/              # Runnable demos
└── docs/                  # Design docs, threat model, benchmarks
```

## Documentation

- [Architecture](ARCHITECTURE.md) — enforcement pipeline, run-state model, behavioral quarantine design
- [Agent Reference Monitor](docs/agent-reference-monitor.md) — the security model in depth
- [Threat Model](docs/threat-model.md) — what Ari Kernel mitigates and what it doesn't
- [Benchmarks](docs/benchmarks.md) — 4 attack stories with unguarded vs. protected outcomes
- [MCP Integration](docs/mcp-integration.md) — `protectMCPTools()` API, auto-taint rules, policy examples
- [Sidecar Mode](docs/sidecar-mode.md) — language-agnostic HTTP enforcement proxy, API reference
- [AgentDojo Benchmark](docs/benchmark-agentdojo.md) — 5-scenario reproducible attack harness

## License

Apache-2.0
