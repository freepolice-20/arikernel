# AriKernel

Runtime firewall for AI agents that blocks prompt injection, tool escalation, and data exfiltration at execution time.

```
┌─────────────┐
│    Agent     │
└──────┬──────┘
       │ tool call
       ▼
┌──────────────────────────────────┐
│          AriKernel               │
│                                  │
│  ┌─ capability token check       │
│  ├─ provenance / taint check     │
│  ├─ behavioral sequence detection│
│  └─ audit log append             │
└──────┬───────────────────────────┘
       │ allowed call
       ▼
┌──────────────────────────────────┐
│  Tools (HTTP / File / Shell / DB)│
└──────────────────────────────────┘
```

## Quick Start

```bash
npm install -g arikernel

arikernel simulate prompt-injection
arikernel trace --latest
arikernel replay --latest --step
```

`simulate` runs a multi-step prompt injection attack through the full enforcement pipeline and writes the audit trail to `./arikernel-audit.db`.

`trace` reads that DB and prints the security execution chain — every tool call, every decision, every taint label.

`replay` walks the same session step by step with timestamps, showing exactly when quarantine fired and why.

**What the output proves:**

- The agent fetched a webpage (allowed), then processed tainted content with a `web` provenance label
- The behavioral rule `web_taint_sensitive_probe` detected the pattern (web taint followed by sensitive file read) and quarantined the session
- The `~/.ssh/id_rsa` read was denied by grant constraint enforcement — the agent only had access to `./data/**`
- Every decision is recorded in a SHA-256 hash-chained audit log that can be independently verified

> **Stale DB:** If you've run simulations before, `--latest` picks the most recent run. To start clean: `rm arikernel-audit.db` before simulating.

### From source

```bash
git clone https://github.com/petermanrique101-sys/AriKernel.git
cd AriKernel
pnpm install && pnpm build
pnpm demo:behavioral    # behavioral quarantine demo
pnpm test
```

## Why AriKernel Exists

AI agents are being given direct access to tools: HTTP requests, shell commands, file I/O, databases. Most deployments rely on prompt-level instructions or static allow/deny lists. Neither is sufficient.

**Prompt filters** operate on text, not on typed actions. They have no concept of data provenance and no enforcement boundary — the LLM can ignore them.

**Static gateways** make binary decisions with no context about where data came from, no token lifecycle, and no behavioral memory across a session.

**AriKernel enforces five layers:**

1. **Short-lived capability tokens** — agents must request and receive a scoped, time-limited, usage-limited token before executing any protected action. Tokens expire after 5 minutes or 10 uses.
2. **Provenance-aware enforcement** — data carries taint labels (`web`, `rag`, `email`) that propagate through tool call chains. Untrusted provenance blocks sensitive operations at the issuance layer.
3. **Behavioral sequence detection** — a recent-event window tracks multi-step patterns across the run. Three built-in rules detect prompt-injection-to-exfiltration sequences and trigger run-level quarantine.
4. **Run-level behavioral quarantine** — when behavioral rules match or denial counters exceed a threshold, the run enters restricted mode. Only read-only safe actions are allowed for the remainder of the session.
5. **Tamper-evident audit evidence** — every decision is logged in a SHA-256 hash-chained event store. Quarantine events, trigger metadata, and matched patterns are first-class audit records.

## CLI

| Command | Description |
|---------|-------------|
| `arikernel simulate [type]` | Run attack simulations (prompt-injection, data-exfiltration, tool-escalation) |
| `arikernel trace [runId]` | Display security execution trace from audit log |
| `arikernel replay [runId]` | Replay a recorded session step by step |
| `arikernel run` | Start firewall in run mode |
| `arikernel policy <file>` | Validate a policy YAML file |
| `arikernel init` | Generate a starter policy file |

All forensic commands default to `./arikernel-audit.db`. Override with `--db <path>`.

### Attack Simulator

```bash
arikernel simulate prompt-injection
arikernel simulate data-exfiltration
arikernel simulate tool-escalation
```

Use a custom policy with `--policy`:

```bash
arikernel simulate prompt-injection --policy policies/safe-defaults.yaml
```

Run all scenarios at once (pass/fail report):

```bash
arikernel simulate
```

### Security Trace

```bash
arikernel trace --latest
arikernel trace <run-id> --db ./arikernel-audit.db
```

### Deterministic Replay

```bash
arikernel replay --latest --verbose
arikernel replay --latest --step    # step-by-step with 800ms delay
```

## Real-World Integration Example

See [examples/langchain-protected-agent/](examples/langchain-protected-agent/) for a self-contained agent that routes all tool calls through AriKernel. It demonstrates:

- Prompt injection detected and blocked in real time
- Behavioral quarantine triggered by tainted content
- Full forensic replay of the session

```bash
npx tsx examples/langchain-protected-agent/agent.ts
arikernel trace --latest
arikernel replay --latest --step
```

## How It Works

```
Agent requests action
        |
        v
  [1] Validate request schema
        |
        v
  [2] Track run-state signals
      - taint observed? -> push to event window
      - sensitive file? -> push to event window
      - egress attempt? -> push to event window
      - behavioral rule match? -> quarantine
        |
        v
  [3] Validate capability token
      - exists, not expired, not revoked?
      - principal, tool class, action match?
      - constraints satisfied?
      - lease not exhausted?
        |
        v
  [4] Evaluate policy rules (priority-sorted, first-match-wins)
        |
        v
  [5] Enforce: ALLOW / DENY / REQUIRE-APPROVAL
        |
        v
  [6] Execute tool, propagate taint
        |
        v
  [7] Audit log (SHA-256 hash chain)
```

Quarantine events are recorded as first-class `_system.quarantine` audit entries with trigger type, matched rule ID, reason, counters snapshot, and the pattern of events that triggered the rule.

**Deployment mode:** AriKernel currently runs in **embedded mode** — the firewall is a library inside the agent process. The agent framework routes tool calls through `createFirewall()`, and the LLM cannot bypass the enforcement pipeline. For production environments that require mandatory enforcement with process isolation, a **proxy/sidecar mode** is on the roadmap where tools are only accessible through the firewall proxy. See [Architecture](ARCHITECTURE.md) for the full trust boundary analysis.

## Behavioral Sequence Rules

Three built-in rules detect suspicious multi-step patterns:

| Rule | Pattern | What it catches |
|------|---------|-----------------|
| `web_taint_sensitive_probe` | Untrusted web/rag/email taint followed by sensitive file read, shell exec, or egress | Prompt injection leading to credential theft |
| `denied_capability_then_escalation` | Denied capability followed by request for a riskier capability class | Automated privilege escalation attempts |
| `sensitive_read_then_egress` | Sensitive file read followed by outbound POST/PUT/PATCH | Data exfiltration sequences |

These rules fire on the recent-event window (last 20 events) and quarantine the run immediately.

## Why It Matters

Every enforcement decision — allow, deny, quarantine — is recorded in a SHA-256 hash-chained audit log. This means:

- **Forensic replay**: reconstruct exactly what an agent did, what was blocked, and why
- **Tamper evidence**: any modification to the log breaks the hash chain
- **Compliance**: prove that security controls were active during every tool call
- **Debugging**: trace behavioral quarantine triggers back to the exact event sequence

The chain from `simulate` to `trace` to `replay` is deterministic. The same audit DB backs all three commands — what you simulate is exactly what you trace and replay.

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

## Framework Adapters

AriKernel provides a lightweight adapter interface so any agent framework can route tool calls through the firewall. The `@arikernel/adapters` package includes:

- **`wrapTool()`** — universal primitive that wraps any tool call with capability + enforcement
- **`LangChainAdapter`** — creates protected tool functions for LangChain DynamicTools
- **`FrameworkAdapter`** interface — implement for CrewAI, OpenAI Assistants, Vercel AI SDK, etc.

### LangChain

```typescript
import { createFirewall } from "@arikernel/runtime";
import { LangChainAdapter } from "@arikernel/adapters/langchain";

const firewall = createFirewall({
  principal: { name: "my-agent", capabilities: [...] },
  policies: "arikernel.policy.yaml",
});

const adapter = new LangChainAdapter(firewall);

// Create protected tool functions
const httpGet = adapter.tool("http", "get");
const fileRead = adapter.tool("file", "read");

// Use with LangChain DynamicTool
new DynamicTool({ name: "http_get", func: (input) => httpGet({ url: input }) });
```

### Generic wrapping (any framework)

```typescript
import { wrapTool } from "@arikernel/adapters";

const protectedHttpGet = wrapTool(firewall, "http", "get");
const result = await protectedHttpGet({ url: "https://example.com" });
```

### Custom adapter

```typescript
import { FrameworkAdapter } from "@arikernel/adapters";

class MyAdapter implements FrameworkAdapter<MyAgent> {
  readonly framework = "my-framework";
  protect(agent: MyAgent): MyAgent { /* wrap tool calls */ }
}
```

## Python Integration (v1)

The v1 Python adapter is a decision/enforcement API layer over the TypeScript core. The server decides allow or deny and writes every decision to the audit log.

```bash
# Start the decision server
pnpm build && pnpm server

# Install the Python client
pip install -e python/
```

```python
from arikernel import FirewallClient, ToolCallDenied

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
```

See [python/README.md](python/README.md) for full API documentation.

## Project Structure

```
arikernel/
├── packages/
│   ├── core/              # Types, Zod schemas, errors, ID generation
│   ├── policy-engine/     # YAML policy loading, priority-sorted rule evaluation
│   ├── taint-tracker/     # Taint label attach, propagate, query
│   ├── audit-log/         # SQLite store, SHA-256 hash chain, replay, system events
│   ├── tool-executors/    # HTTP, file, shell, database executors
│   ├── runtime/           # Firewall, Pipeline, CapabilityIssuer, TokenStore,
│   │                      # RunStateTracker, behavioral rules
│   ├── attack-sim/        # Attack scenario runner + interactive simulator
│   └── adapters/          # Framework adapters (LangChain, generic wrapTool)
├── apps/
│   ├── cli/               # CLI (init, policy, replay, simulate, trace)
│   └── server/            # HTTP decision server for cross-language integration
├── python/                # Python client (v1 decision/enforcement adapter)
├── policies/              # YAML policy files
├── examples/              # Runnable demos
└── docs/                  # Design docs, threat model, benchmarks
```

## Documentation

- [Agent Reference Monitor](docs/agent-reference-monitor.md) — the security model: ambient authority, why per-call gateways fail, and how the reference monitor enforces capability + provenance + behavioral quarantine
- [Architecture](ARCHITECTURE.md) — enforcement pipeline, run-state model, run-level behavioral quarantine design
- [Threat Model](docs/threat-model.md) — what this mitigates (per-call and behavioral) and what it doesn't
- [Benchmarks](docs/benchmarks.md) — 4 attack stories with attacker goal, sequence, unguarded outcome vs. AriKernel outcome, and what the audit replay proves

## License

Apache-2.0
