# Agent Firewall

A reference monitor for AI agents. Intercepts every tool call at runtime, enforces short-lived capability tokens, tracks data provenance, detects multi-step attack patterns, and produces replayable audit evidence.

**Core thesis:** AI agents should never execute with ambient authority. Every tool call must pass through an enforcement boundary that validates capability tokens, checks data provenance, evaluates behavioral patterns, and logs a tamper-evident decision — before anything executes.

## Why This Exists

AI agents are being given direct access to tools: HTTP requests, shell commands, file I/O, databases. Most deployments rely on prompt-level instructions or static allow/deny lists. Neither is sufficient.

**Prompt filters** operate on text, not on typed actions. They have no concept of data provenance and no enforcement boundary — the LLM can ignore them.

**Static gateways** make binary decisions with no context about where data came from, no token lifecycle, and no behavioral memory across a session.

**Agent Firewall enforces five layers:**

1. **Short-lived capability tokens** — agents must request and receive a scoped, time-limited, usage-limited token before executing any protected action. Tokens expire after 5 minutes or 10 uses.
2. **Provenance-aware enforcement** — data carries taint labels (`web`, `rag`, `email`) that propagate through tool call chains. Untrusted provenance blocks sensitive operations at the issuance layer.
3. **Behavioral sequence detection** — a recent-event window tracks multi-step patterns across the run. Three built-in rules detect prompt-injection-to-exfiltration sequences and trigger run-level quarantine before threshold counters would.
4. **Run-level behavioral quarantine** — when behavioral rules match or denial counters exceed a threshold, the run enters restricted mode. Only read-only safe actions are allowed for the remainder of the session.
5. **Replayable audit evidence** — every decision is logged in a SHA-256 hash-chained event store. Quarantine events, trigger metadata, and matched patterns are first-class audit records.

## Quick Start

```bash
# Prerequisites: Node.js >= 20, pnpm >= 9
git clone https://github.com/petermanrique101-sys/Agent-Firewall.git
cd Agent-Firewall
pnpm install && pnpm build
```

### Run the behavioral enforcement demo

```bash
pnpm demo:behavioral
```

This simulates an agent that receives tainted web content and then attempts to read SSH keys. The behavioral rule `web_taint_sensitive_probe` detects the pattern and quarantines the run — with only 1 denied action, far below the threshold of 10.

### Replay the audit trail

```bash
pnpm cli replay --latest --verbose --db ./demo-audit.db
```

```
────────────────────────────────────────────────────────
 Audit Replay
────────────────────────────────────────────────────────
  Run ID:    01KK3G3W...
  Principal: 01KK3G3W...
  Started:   2026-03-07T06:35:19.126Z
  Ended:     2026-03-07T06:35:19.610Z
────────────────────────────────────────────────────────

  #0 ALLOW http.get  [token:01KK3G3W...]  226ms
     Reason: HTTP GET requests are allowed (read-only)

  #1 ALLOW http.get  [token:01KK3G3W...]  246ms
     Reason: HTTP GET requests are allowed (read-only)
     Taint:  web:httpbin.org/html

  #2 QUARANTINE  Run entered restricted mode
     Trigger: behavioral_rule (web_taint_sensitive_probe)
     Reason:  Untrusted web input was followed by file.read attempt
     Pattern: taint_observed(http) → sensitive_read_attempt(file)

  #3 DENY  file.read  [token:01KK3G3W...]
     Reason: Grant constraint violation: Path '~/.ssh/id_rsa' not in allowed paths

  #4 DENY  http.post  [no token]
     Reason: Run entered restricted mode [...] 'http.post' is blocked.

────────────────────────────────────────────────────────
 Summary

  Total events:       5
  Allowed:            2
  Denied:             2
  Quarantine events:  1

  Hash chain:         VALID
────────────────────────────────────────────────────────
```

Every event carries full provenance. The QUARANTINE record shows the trigger type, matched rule, reason, and the pattern of events that fired it. The hash chain is cryptographically verified on replay.

### All demos

```bash
pnpm demo              # Core pipeline: allow, deny, approval, taint, audit replay
pnpm demo:capability   # Capability issuance: taint-aware token granting and denial
pnpm demo:attack       # Prompt injection: 4-stage attack blocked by 4 defense layers
pnpm demo:escalation   # Privilege escalation: narrow token cannot be widened
pnpm demo:run-state    # Threshold-based quarantine after repeated denied actions
pnpm demo:behavioral   # Behavioral sequence enforcement: pattern-based quarantine
```

### Tests

```bash
pnpm test
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

## Behavioral Sequence Rules

Three built-in rules detect suspicious multi-step patterns:

| Rule | Pattern | What it catches |
|------|---------|-----------------|
| `web_taint_sensitive_probe` | Untrusted web/rag/email taint followed by sensitive file read, shell exec, or egress | Prompt injection leading to credential theft |
| `denied_capability_then_escalation` | Denied capability followed by request for a riskier capability class | Automated privilege escalation attempts |
| `sensitive_read_then_egress` | Sensitive file read followed by outbound POST/PUT/PATCH | Data exfiltration sequences |

These rules fire on the recent-event window (last 20 events) and quarantine the run immediately. No DSL, no graph engine — explicit pattern matching in code.

## Project Structure

```
agent-firewall/
├── packages/
│   ├── core/              # Types, Zod schemas, errors, ID generation
│   ├── policy-engine/     # YAML policy loading, priority-sorted rule evaluation
│   ├── taint-tracker/     # Taint label attach, propagate, query
│   ├── audit-log/         # SQLite store, SHA-256 hash chain, replay, system events
│   ├── tool-executors/    # HTTP, file, shell, database executors
│   ├── runtime/           # Firewall, Pipeline, CapabilityIssuer, TokenStore,
│   │                      # RunStateTracker, behavioral rules
│   └── attack-sim/        # Attack scenario runner
├── apps/
│   ├── cli/               # CLI (init, policy validate, replay, simulate)
│   └── server/            # HTTP decision server for cross-language integration
├── python/                # Python client (v1 decision/enforcement adapter)
├── policies/              # YAML policy files
├── examples/              # Runnable demos
└── docs/                  # Threat model, benchmarks, architecture
```

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

## Python Integration (v1)

The v1 Python adapter is a decision/enforcement API layer over the TypeScript core. The server decides allow or deny and writes every decision to the audit log.

```bash
# Start the decision server
pnpm build && pnpm server

# Install the Python client
pip install -e python/
```

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
```

See [python/README.md](python/README.md) for full API documentation.

## Documentation

- [Architecture](ARCHITECTURE.md) — enforcement pipeline, run-state model, behavioral quarantine design
- [Threat Model](docs/threat-model.md) — what this mitigates (per-call and behavioral) and what it doesn't
- [Benchmarks](docs/benchmarks.md) — 4 attack stories: attacker goal, sequence, unguarded outcome vs. Agent Firewall outcome, and what the audit replay proves

## License

Apache-2.0
