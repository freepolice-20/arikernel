# Ari Kernel — Architecture

> A runtime security enforcement layer for AI agents, drawing on the reference monitor concept (Anderson, 1972).
> Intercepts tool calls at the execution boundary and enforces security before anything executes. The degree to which classical reference monitor properties hold depends on deployment mode (see § 12).

## 1. Technical Architecture

Ari Kernel is a **synchronous intercept runtime**. It sits in the call path between an AI agent and its tools. Every tool call passes through a pipeline:

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
└───────────────┬───────────────────┘
                │ allow / deny / quarantine
                ▼
  Protected Tools / Resources
  files │ http │ shell │ db │ retrieval │ mcp
```

**Key architectural properties:**
- **Synchronous by default** -- the agent blocks until the kernel returns a decision
- **Deny-by-default** -- if no policy explicitly allows a tool call, it is denied
- **Capability-scoped** -- agents are principals with explicitly granted capabilities, no ambient authority
- **Taint-aware** -- every piece of data carries provenance labels, taint propagates forward through tool call chains
- **Append-only audit** -- every decision is logged with a hash chain for tamper evidence

The runtime is a **library first**, not a server. You `import { createKernel } from '@arikernel/runtime'` and wrap your agent's tool calls. A CLI and sidecar proxy are layered on top.

See also: [Security Model](docs/security-model.md) | [Threat Model](docs/threat-model.md)

---

## 2. Stack

| Layer | Choice | Why |
|-------|--------|-----|
| Language | TypeScript 5.x (strict mode) | Good type system for domain modeling. Large ecosystem. |
| Runtime | Node.js 20+ | LTS, stable. |
| Monorepo | pnpm workspaces + Turborepo | Fast, reliable, well-understood. |
| Validation | Zod | Runtime schema validation that generates TS types. Single source of truth. |
| Audit storage | better-sqlite3 | Embedded, zero-config, fast synchronous writes. |
| Policy format | YAML (parsed with yaml lib) | Human-readable, diffable, git-friendly. |
| Testing | Vitest | Fast, native ESM, TS-first. |
| Build | tsup | Simple, fast TS bundler. |
| Linting | Biome | Fast, single tool for lint + format. |
| CLI framework | citty (from unjs) | Lightweight, typed, no decorators. |

---

## 3. Monorepo Structure

```
arikernel/
├── packages/
│   ├── core/                          # Shared domain types, Zod schemas, presets
│   ├── policy-engine/                 # YAML policy loading, rule evaluation
│   ├── taint-tracker/                 # Taint label management and propagation
│   ├── audit-log/                     # SQLite store, SHA-256 hash chain, replay
│   ├── tool-executors/                # HTTP, file, shell, database, retrieval executors
│   ├── runtime/                       # Kernel, pipeline, capability issuer, behavioral rules, trace/replay
│   ├── adapters/                      # Framework adapters (LangChain, OpenAI, CrewAI, Vercel AI, etc.)
│   ├── mcp-adapter/                   # MCP tool integration
│   ├── sidecar/                       # Standalone HTTP proxy enforcement
│   ├── attack-sim/                    # Attack scenario runner
│   └── benchmarks-agentdojo/          # AgentDojo-aligned benchmark harness
├── apps/
│   ├── cli/                           # CLI application (arikernel binary)
│   └── server/                        # HTTP decision server (legacy, port 9099)
├── python/                            # Python runtime (experimental — not in v0.1.0)
├── policies/                          # YAML policy files (safe-defaults, deny-all)
├── examples/                          # Runnable demos
├── docs/                              # Design docs, threat model, benchmarks
└── benchmarks/                        # Benchmark results
```

---

## 4. Core Domain Model

### Principal (the agent identity)

```typescript
type ToolClass = 'http' | 'file' | 'shell' | 'database' | 'retrieval' | 'mcp';

interface Capability {
  toolClass: ToolClass;
  actions?: string[];                    // e.g. ['read'] for file. Empty = all actions.
  constraints?: {
    allowedPaths?: string[];             // file: glob patterns
    allowedHosts?: string[];             // http: hostname allowlist
    allowedCommands?: string[];          // shell: command allowlist
    allowedDatabases?: string[];         // database: db name allowlist
    maxCallsPerMinute?: number;          // rate limit
  };
}

interface Principal {
  id: string;                            // ULID
  name: string;                          // human-readable, e.g. "research-agent"
  capabilities: Capability[];
}
```

### ToolCall (what the agent wants to do)

```typescript
interface ToolCall {
  id: string;                            // ULID, assigned by runtime
  runId: string;                         // groups calls in a single agent run
  sequence: number;                      // order within the run
  timestamp: string;                     // ISO 8601
  principalId: string;
  toolClass: ToolClass;
  action: string;                        // 'read' | 'write' | 'get' | 'post' | 'exec' | 'query'
  parameters: Record<string, unknown>;   // tool-specific params
  taintLabels: TaintLabel[];             // taint on the inputs
  parentCallId?: string;                 // if this call was triggered by another
}

interface ToolResult {
  callId: string;
  success: boolean;
  data?: unknown;
  error?: string;
  taintLabels: TaintLabel[];             // taint propagated to output
  durationMs: number;
}
```

### TaintLabel (data provenance)

```typescript
type TaintSource =
  | 'web'                // fetched from the internet
  | 'rag'                // retrieved from a vector store / RAG pipeline
  | 'email'              // from email content
  | 'retrieved-doc'      // from document retrieval
  | 'model-generated'    // produced by the LLM itself
  | 'user-provided'      // direct user input (trusted by default)
  | 'tool-output';       // output from a previous tool call

interface TaintLabel {
  source: TaintSource;
  origin: string;                        // human-readable origin, e.g. "google.com", "rag:docs-collection"
  confidence: number;                    // 0.0-1.0, how confident we are this is tainted
  addedAt: string;                       // ISO 8601
  propagatedFrom?: string;               // callId of the originating tool call
}
```

### Policy (rules that govern decisions)

```typescript
type DecisionVerdict = 'allow' | 'deny' | 'require-approval';

interface PolicyMatch {
  toolClass?: ToolClass | ToolClass[];
  action?: string | string[];
  principalId?: string;
  taintSources?: TaintSource[];          // match if ANY of these taints are present
  parameters?: Record<string, {
    pattern?: string;                    // regex pattern to match param value
    in?: string[];                       // param value must be in this list
    notIn?: string[];                    // param value must not be in this list
  }>;
}

interface PolicyRule {
  id: string;
  name: string;
  description?: string;
  priority: number;                      // lower = evaluated first. 0-999.
  match: PolicyMatch;
  decision: DecisionVerdict;
  reason: string;                        // human-readable reason for this rule
  tags?: string[];                       // for organization
}
```

### AuditEvent (the immutable record)

```typescript
interface AuditEvent {
  id: string;                            // ULID
  runId: string;
  sequence: number;
  timestamp: string;
  principalId: string;
  toolCall: ToolCall;
  decision: Decision;
  result?: ToolResult;                   // present only if executed
  previousHash: string;                  // SHA-256 of previous event (hash chain)
  hash: string;                          // SHA-256 of this event
}
```

---

## 5. Services and Responsibilities

### PolicyEngine
```
Input:  ToolCall + TaintLabel[] + Capability[]
Output: Decision

Responsibilities:
- Load policy rules from YAML files
- Validate rules against Zod schema
- Merge policy layers (defaults < project < runtime overrides)
- Evaluate rules in priority order against a ToolCall
- Return first matching rule's decision, or implicit deny
```

### TaintTracker
```
Input:  ToolCall inputs, previous ToolResults
Output: TaintLabel[] for this call, TaintLabel[] for the result

Responsibilities:
- Attach taint labels to incoming data at system boundaries
- Propagate taint from tool call inputs to outputs
- Merge taint labels when multiple tainted sources combine
- Provide query interface: "is this data tainted by source X?"
- Taint is additive and monotonic -- never removed, only acknowledged
```

### AuditStore
```
Input:  AuditEvent
Output: void (append), AuditEvent[] (query), RunContext (replay)

Responsibilities:
- Append events to SQLite with hash chain
- Verify hash chain integrity on read
- Query events by runId, time range, toolClass, verdict
- Export run for replay
```

### ToolExecutor (per tool class)
```
Input:  ToolCall (already approved by policy engine)
Output: ToolResult

Responsibilities:
- Execute the actual tool action (HTTP request, file read, etc.)
- Enforce hard safety limits (timeouts, max response size)
- SSRF protection on HTTP executor (private IP blocking, redirect validation)
- Path canonicalization on file executor (symlink resolution)
- Command validation on shell executor (metacharacter blocking)
- Capture output and timing
- Attach taint labels to output
- Never called directly -- only through the runtime pipeline
```

### Runtime (the orchestrator)
```
Input:  FirewallConfig, ToolCall request from agent
Output: ToolResult or DeniedError

Responsibilities:
- The main intercept loop
- Manages lifecycle: init, intercept, shutdown
- Wires together PolicyEngine, TaintTracker, AuditStore, ToolExecutors
- Provides hooks for extensibility (onDecision, onExecute, onAudit)
- Exposes the public API: createKernel() and createFirewall()
```

---

## 6. Audit Event Schema (SQLite)

```sql
CREATE TABLE IF NOT EXISTS runs (
  run_id        TEXT PRIMARY KEY,
  principal_id  TEXT NOT NULL,
  started_at    TEXT NOT NULL,
  ended_at      TEXT,
  event_count   INTEGER DEFAULT 0,
  config_json   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  id            TEXT PRIMARY KEY,
  run_id        TEXT NOT NULL REFERENCES runs(run_id),
  sequence      INTEGER NOT NULL,
  timestamp     TEXT NOT NULL,
  principal_id  TEXT NOT NULL,
  tool_class    TEXT NOT NULL,
  action        TEXT NOT NULL,
  tool_call_json TEXT NOT NULL,
  decision_json  TEXT NOT NULL,
  result_json    TEXT,
  duration_ms    INTEGER,
  taint_sources  TEXT NOT NULL,
  verdict        TEXT NOT NULL,
  previous_hash  TEXT NOT NULL,
  hash           TEXT NOT NULL,
  UNIQUE(run_id, sequence)
);

CREATE INDEX idx_events_run ON events(run_id, sequence);
CREATE INDEX idx_events_time ON events(timestamp);
CREATE INDEX idx_events_verdict ON events(verdict);
CREATE INDEX idx_events_tool ON events(tool_class, action);
```

---

## 7. Policy Engine Design

**Evaluation order:**

```
1. Built-in defaults (deny-all at priority 999, always last)
2. Project policies (priority 100-899)       -- from arikernel.policy.yaml
3. Runtime overrides (priority 900-999)      -- passed programmatically
```

Lower priority number = evaluated first. First match wins.

**Policy YAML format:**

```yaml
# arikernel.policy.yaml
name: my-project-policy
version: "1.0"

rules:
  - id: allow-safe-http-reads
    name: Allow HTTP GET to known APIs
    priority: 100
    match:
      toolClass: http
      action: get
      parameters:
        url:
          pattern: "^https://(api\\.github\\.com|api\\.openai\\.com)"
    decision: allow
    reason: "Known safe API endpoints"

  - id: deny-tainted-shell
    name: Deny shell commands with web-tainted input
    priority: 150
    match:
      toolClass: shell
      taintSources: [web, rag, email]
    decision: deny
    reason: "Shell execution with untrusted input is forbidden"

  - id: approve-file-writes
    name: Require approval for file writes
    priority: 200
    match:
      toolClass: file
      action: write
    decision: require-approval
    reason: "File writes require human approval"
```

**Matcher logic:**

```
evaluate(toolCall, taintLabels, capabilities):
  // Step 1: capability check (before policy)
  if not principalHasCapability(toolCall.principalId, toolCall.toolClass):
    return Decision { verdict: 'deny', reason: 'No capability grant' }

  // Step 2: constraint check
  if not constraintsSatisfied(toolCall, capability.constraints):
    return Decision { verdict: 'deny', reason: 'Constraint violation: ...' }

  // Step 3: policy rules (sorted by priority)
  for rule in sortedRules:
    if matches(rule.match, toolCall, taintLabels):
      return Decision { verdict: rule.decision, matchedRule: rule }

  // Step 4: implicit deny
  return Decision { verdict: 'deny', reason: 'No matching policy (deny-by-default)' }
```

---

## 8. Taint-Tracking Model

**Core principles:**
1. Taint is attached at **system boundaries** -- when data enters from an untrusted source
2. Taint **propagates forward** -- if a tool call's inputs are tainted, its outputs inherit those taints
3. Taint is **monotonic** -- you can add taints, never remove them
4. Taint is **queryable** -- policies can match on taint sources

**Propagation rules:**

```
Rule 1: ATTACH
  When data enters from external source -> attach TaintLabel with source type
  Examples:
    - HTTP response body -> taint: 'web'
    - RAG retrieval result -> taint: 'rag'
    - Email content parsed -> taint: 'email'
    - LLM-generated plan -> taint: 'model-generated'

Rule 2: PROPAGATE
  When a tool call has tainted inputs -> output inherits all input taints
  Output gets: union of all input taints + new taint('tool-output')

Rule 3: MERGE
  When multiple tainted values combine -> result has union of all taints

Rule 4: NEVER STRIP
  Taint is never removed. Policy can explicitly ALLOW despite taint,
  but the taint label stays on the data for audit purposes.
```

**Interface:**

```typescript
class TaintTracker {
  attach(data: unknown, source: TaintSource, origin: string): TaintedValue;
  collectInputTaints(toolCall: ToolCall): TaintLabel[];
  propagate(inputTaints: TaintLabel[], callId: string): TaintLabel[];
  hasTaint(labels: TaintLabel[], source: TaintSource): boolean;
}
```

---

## 9. Runtime Execution Flow

```
Agent calls: kernel.execute({ toolClass: 'http', action: 'get', parameters: { url: '...' } })
       |
       v
  1. VALIDATE
     - Parse + validate ToolCall via Zod
     - Assign ID, timestamp, sequence
       |
       v
  2. CHECK RUN-STATE
     - If quarantined, deny non-safe actions immediately
       |
       v
  3. CHECK CAPABILITY TOKEN
     - Verify valid, unexpired token for this tool class + action
       |
       v
  4. COLLECT TAINT
     - TaintTracker.collectInputTaints()
     - Attach any new taints from params
       |
       v
  5. EVALUATE POLICY
     - Check constraints
     - Evaluate policy rules
     - Return Decision
       |
       v
  6. ENFORCE DECISION
     - DENY: log + throw ToolCallDeniedError
     - REQUIRE-APPROVAL: call approval handler, block until resolved
     - ALLOW: continue to execution
       |
       v
  7. EXECUTE
     - Route to correct ToolExecutor
     - Execute with timeout + limits
     - Capture result or error
       |
       v
  8. PROPAGATE TAINT
     - Apply input taints to output
     - Add tool-output taint
       |
       v
  9. AUDIT LOG
     - Create AuditEvent
     - Compute hash chain
     - Append to SQLite
       |
       v
  10. EVALUATE BEHAVIORAL RULES
     - Push security events to recent-event window
     - Evaluate 6 behavioral rules
     - Quarantine if pattern matched
       |
       v
  Return ToolResult to agent
```

**Public API surface:**

```typescript
import { createKernel } from '@arikernel/runtime';

const kernel = createKernel({
  preset: 'safe-research',
  auditLog: './audit.db',
});

// Intercept a tool call
const result = await kernel.execute({
  toolClass: 'http',
  action: 'get',
  parameters: { url: 'https://api.github.com/repos/...' },
});

// Shutdown
kernel.close();
```

Or with explicit principal and policy configuration:

```typescript
import { createFirewall } from '@arikernel/runtime';

const firewall = createFirewall({
  principal: {
    name: 'my-agent',
    capabilities: [
      { toolClass: 'http', actions: ['get'], constraints: { allowedHosts: ['api.github.com'] } },
      { toolClass: 'file', actions: ['read'], constraints: { allowedPaths: ['./data/**'] } },
    ],
  },
  policies: './arikernel.policy.yaml',
  auditLog: './audit.db',
});
```

---

## 10. Run-State Enforcement and Behavioral Quarantine

The pipeline in section 9 handles per-call enforcement. Run-state enforcement adds a **session-level** layer that tracks cumulative behavior and detects multi-step attack patterns.

### Run-State Counters

The `RunStateTracker` maintains counters across the entire agent run:

| Counter | Tracks |
|---------|--------|
| `deniedActions` | Total denied tool calls |
| `capabilityRequests` | Total capability requests |
| `deniedCapabilityRequests` | Denied capability requests |
| `externalEgressAttempts` | HTTP POST/PUT/PATCH/DELETE attempts |
| `sensitiveFileReadAttempts` | Reads targeting `.ssh`, `.env`, `.aws`, `credentials`, etc. |

When `deniedActions` exceeds a configurable threshold (default: 5), the run enters **restricted mode**. Only safe read-only actions are permitted for the remainder of the session.

### Recent-Event Window

A bounded in-memory buffer (max 20 entries) of normalized `SecurityEvent` objects. Events are pushed by the Pipeline (taint, tool call, egress, sensitive read signals) and Firewall (capability request/grant/deny signals). The window enables behavioral sequence detection without unbounded state.

Event types: `capability_requested`, `capability_denied`, `capability_granted`, `tool_call_allowed`, `tool_call_denied`, `taint_observed`, `sensitive_read_attempt`, `sensitive_read_allowed`, `egress_attempt`, `quarantine_entered`.

### Behavioral Sequence Rules

Six rules evaluated after every security event push. No DSL, no graph engine — direct pattern matching in code.

| Rule | Pattern | Catches |
|------|---------|---------|
| `web_taint_sensitive_probe` | Web/rag/email taint → sensitive read, shell exec, or egress | Prompt injection → credential theft |
| `denied_capability_then_escalation` | Denied capability → request for riskier class (risk: http=1 < database=2 < file=3 < shell=5) | Automated privilege escalation |
| `sensitive_read_then_egress` | Sensitive file read → outbound POST/PUT/PATCH | Data exfiltration sequences |
| `tainted_database_write` | Web/rag/email taint → database write/exec/mutate | Tainted SQL injection |
| `tainted_shell_with_data` | Web/rag/email taint → shell exec with long command string (>100 chars) | Data piping via shell arguments |
| `secret_access_then_any_egress` | Secret/credential resource access (DB queries to secrets tables, HTTP to vault endpoints) → any egress | Credential theft |

First matching rule wins. When a rule matches, the run is quarantined immediately.

### Quarantine

Both threshold-based and behavioral-rule-based triggers produce a `QuarantineInfo` record containing: trigger type, rule ID, reason, counters snapshot, matched events, and timestamp.

Quarantine is recorded as a first-class `_system.quarantine` audit event that participates in the hash chain. The `appendSystemEvent()` method on `AuditStore` creates a synthetic tool call with `toolClass: '_system'` and stores the quarantine metadata in the parameters field.

### Restricted Mode Enforcement

Once quarantined, the Pipeline rejects non-safe actions before policy evaluation. The Firewall rejects non-safe capability issuances. Only `http.get/head/options`, `file.read`, and `database.query` pass through.

### Tamper-Evident Audit Evidence

The CLI `replay` command renders quarantine events with trigger type, rule ID, reason, counters snapshot, and matched event pattern:

```bash
pnpm ari replay --latest --verbose --db ./demo-audit.db
```

---

## 11. Deterministic Trace Recording and Replay

Ari Kernel can record a run as a JSON trace file and replay it through a fresh kernel instance to verify that every enforcement decision is deterministic.

**Recording:** `TraceRecorder` hooks into the kernel's lifecycle hooks to capture events non-intrusively during a live run. Traces include tool call requests, capability grants, policy decisions, behavioral matches, quarantine events, and counters snapshots.

**Replay:** `replayTrace()` creates a fresh kernel, feeds the recorded requests through it, and compares every decision. Executors are stubbed during replay — no external side effects are re-executed.

**What-if analysis:** Replay with a different policy or preset to see how decisions would change. This supports policy regression testing and compliance analysis.

```bash
# Record and replay
pnpm demo:replay

# Replay a trace file via CLI
pnpm ari replay-trace demo-trace.json --verbose

# What-if: replay with a different preset
pnpm ari replay-trace demo-trace.json --preset workspace-assistant
```

See [Deterministic Replay](docs/replay.md) for the full API reference.

---

## 12. Deployment Modes and Trust Boundaries

Ari Kernel can be deployed in two modes. The deployment mode determines where the trust boundary sits and what guarantees the system provides.

### Embedded Mode

```
┌──────────────────────────────────────┐
│          Agent Process               │
│                                      │
│  Agent Code                          │
│      ↓                               │
│  createKernel()    ← trust boundary  │
│      ↓                               │
│  Tool Executors                      │
└──────────────────────────────────────┘
```

In embedded mode, the kernel runs as a library inside the agent process. The agent framework imports `createKernel()` and routes tool calls through it. This is **cooperative enforcement**: the agent framework must opt in to the kernel by wrapping tool execution.

**Trust boundary:** The kernel code itself is trusted — it runs in the same process but is not controlled by the LLM. The LLM's tool calls pass through the enforcement pipeline before reaching executors. The LLM cannot modify the kernel's policy, tokens, or audit log, because those are runtime objects outside its control. However, if the agent framework code itself is compromised or misconfigured to bypass the kernel, enforcement is lost.

**When to use:** Development, integration testing, single-process agents, environments where you control the agent framework code. This is the right mode when the agent framework is trusted and the threat is adversarial LLM behavior (prompt injection, jailbreaks), not adversarial framework code.

**Guarantees:**
- Every tool call routed through the kernel is subject to full enforcement (capability, taint, behavioral, audit)
- The LLM cannot bypass the kernel — it can only call functions the framework exposes
- Audit log integrity is protected by the SHA-256 hash chain (tamper-evident, not tamper-proof within the same process)

### Sidecar / Proxy Mode

```
┌─────────────────┐     ┌──────────────────────┐     ┌───────────┐
│  Agent Process   │     │  Sidecar Process     │     │  Tools    │
│                  │     │                      │     │           │
│  Agent Code ─────┼────→│  capability check    │────→│  HTTP     │
│                  │     │  taint check         │     │  File     │
│  (no direct      │     │  behavioral rules    │     │  Shell    │
│   tool access)   │     │  audit log           │     │  Database │
└─────────────────┘     └──────────────────────┘     └───────────┘
```

In sidecar mode, the kernel runs as a separate HTTP process on port 8787. Tools are not directly accessible to the agent — all tool calls must pass through the sidecar via `POST /execute`. The agent process has no access to the policy engine, run-state, or audit log.

**Trust boundary:** The kernel is a separate process with its own memory space. The agent cannot modify kernel state, bypass enforcement, or tamper with the audit log. This is **mandatory enforcement**: there is no code path from the agent to tools that does not pass through the kernel.

**When to use:** Production deployments, untrusted agent code, polyglot environments, compliance-sensitive workloads. This is the right mode when you need to guarantee enforcement regardless of what the agent framework does.

**Guarantees:**
- Mandatory mediation — no tool call can reach executors without passing through the sidecar, provided the agent has no alternative network path or filesystem access to tools outside the sidecar
- Process isolation — agent cannot inspect or modify firewall state or audit log (separate address space)
- Tamper-evident audit — audit log is in a separate process with a SHA-256 hash chain. Process separation prevents the agent from modifying the log, but does not prevent tampering by an attacker with host-level access (see § 13)
- Supports any language or framework — agent communicates via HTTP
- Per-principal isolation — each principal gets an independent kernel instance

### Trust Boundary Comparison

| Property | Embedded Mode | Sidecar Mode |
|----------|--------------|------------|
| Enforcement type | Cooperative | Mandatory |
| Agent can bypass? | Only if framework code is modified to skip enforcement | No — no direct path to tools |
| Audit tamper resistance | Tamper-evident (hash chain, same process) | Tamper-evident + process-isolated (agent cannot access audit DB) |
| Language support | TypeScript/JavaScript (Python experimental, not in v0.1.0) | Any (HTTP API) |
| Latency | In-process (microseconds) | Network hop (milliseconds) |
| Setup complexity | `npm install` + `createKernel()` | Separate service deployment |

The sidecar server (`packages/sidecar/`) implements proxy mode. See [Sidecar Mode](docs/sidecar-mode.md) for API reference.

---

## 13. Known Limitations and Design Tradeoffs

### Current Limitations

1. **In-memory TokenStore** — grants are lost on process restart. Production use requires persistent storage.
2. **Single-process** — no distributed token validation. Tokens are only valid within the process that issued them.
3. **Database executor is a stub** — validates and audits calls but does not execute real queries.
4. **Retrieval executor is a stub** — validates and audits calls but does not execute real lookups.
5. **Static principal** — the principal is configured at kernel creation time. There is no dynamic principal resolution or authentication.
6. **Taint labeling is partially automatic** — HTTP, RAG, and MCP executors auto-attach provenance labels. Other sources (email, custom inputs) require manual labeling.
7. **YAML policies only** — no API for dynamic policy updates at runtime.

### Key Design Tradeoffs

1. **Library-first, not server-first** — Lower adoption friction
2. **Synchronous intercept, not async** — Simpler mental model
3. **SQLite, not Postgres** — Zero infra dependency
4. **YAML policies, not code policies** — Declarative, diffable, non-dev-accessible
5. **ToolCall-level taint, not field-level** — Covers most cases with lower complexity
6. **Hardcoded behavioral rules, not a DSL** — Predictable, testable, no interpretation ambiguity
