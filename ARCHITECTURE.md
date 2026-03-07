# Agent Firewall -- MVP Architecture Spec

> The browser security model for AI agents.
> A runtime enforcement layer between agents and tools.

## 1. Technical Architecture

Agent Firewall is a **synchronous intercept runtime**. It sits in the call path between an AI agent and its tools. Every tool call passes through a pipeline:

```
Agent --> Firewall Runtime --> Policy Engine --> Tool Executor --> Audit Log
                                  |                                   |
                            Taint Tracker                        Hash Chain
```

**Key architectural properties:**
- **Synchronous by default** -- the agent blocks until the firewall returns a decision
- **Deny-by-default** -- if no policy explicitly allows a tool call, it is denied
- **Capability-scoped** -- agents are principals with explicitly granted capabilities, no ambient authority
- **Taint-aware** -- every piece of data carries provenance labels, taint propagates forward through tool call chains
- **Append-only audit** -- every decision is logged with a hash chain for tamper evidence

The runtime is a **library first**, not a server. You `import { createFirewall } from '@agent-firewall/runtime'` and wrap your agent's tool calls. A CLI and (later) a hosted control plane are layered on top.

---

## 2. Stack

| Layer | Choice | Why |
|-------|--------|-----|
| Language | TypeScript 5.x (strict mode) | Good type system for domain modeling. Large ecosystem. |
| Runtime | Node.js 20+ | LTS, stable, boring. |
| Monorepo | pnpm workspaces + Turborepo | Fast, reliable, well-understood. |
| Validation | Zod | Runtime schema validation that generates TS types. Single source of truth. |
| Audit storage | better-sqlite3 | Embedded, zero-config, fast synchronous writes. Perfect for local-first. |
| Policy format | YAML (parsed with yaml lib) | Human-readable, diffable, git-friendly. |
| Testing | Vitest | Fast, native ESM, TS-first. |
| Build | tsup | Simple, fast TS bundler. |
| Linting | Biome | Fast, single tool for lint + format. |
| CLI framework | citty (from unjs) | Lightweight, typed, no decorators. |

**What we're NOT using and why:**
- No Express/Fastify -- this is a library, not a server (yet)
- No Prisma/Drizzle -- raw better-sqlite3 is enough for append-only logs
- No custom DSL for policies -- YAML + Zod validation is sufficient
- No Redis/Postgres -- embedded SQLite keeps the MVP zero-dependency for infra
- No React dashboard -- CLI first, dashboard later

---

## 3. Monorepo Structure

```
agent-firewall/
├── packages/
│   ├── core/                          # Shared domain types + utilities
│   │   ├── src/
│   │   │   ├── types/
│   │   │   │   ├── principal.ts       # Principal, Capability
│   │   │   │   ├── tool-call.ts       # ToolCall, ToolClass, ToolResult
│   │   │   │   ├── taint.ts           # TaintLabel, TaintSource
│   │   │   │   ├── policy.ts          # PolicyRule, PolicyMatch, Decision
│   │   │   │   ├── audit.ts           # AuditEvent, RunContext
│   │   │   │   └── index.ts           # Re-exports
│   │   │   ├── schemas/
│   │   │   │   ├── tool-call.schema.ts
│   │   │   │   ├── policy.schema.ts
│   │   │   │   └── config.schema.ts
│   │   │   ├── errors.ts              # Typed error classes
│   │   │   ├── id.ts                  # ID generation (ULID)
│   │   │   └── index.ts
│   │   ├── package.json
│   │   └── tsconfig.json
│   │
│   ├── policy-engine/                 # Policy evaluation
│   │   ├── src/
│   │   │   ├── engine.ts             # PolicyEngine class
│   │   │   ├── matcher.ts            # Rule matching logic
│   │   │   ├── loader.ts             # YAML policy file loader
│   │   │   ├── defaults.ts           # Built-in deny-all + safe defaults
│   │   │   └── index.ts
│   │   ├── __tests__/
│   │   │   ├── engine.test.ts
│   │   │   └── matcher.test.ts
│   │   ├── package.json
│   │   └── tsconfig.json
│   │
│   ├── taint-tracker/                 # Taint label management
│   │   ├── src/
│   │   │   ├── tracker.ts            # TaintTracker class
│   │   │   ├── propagation.ts        # Propagation rules
│   │   │   ├── labels.ts             # Label factory + helpers
│   │   │   └── index.ts
│   │   ├── __tests__/
│   │   │   └── tracker.test.ts
│   │   ├── package.json
│   │   └── tsconfig.json
│   │
│   ├── audit-log/                     # Immutable event logging
│   │   ├── src/
│   │   │   ├── store.ts              # AuditStore (SQLite)
│   │   │   ├── hash-chain.ts         # SHA-256 hash chain
│   │   │   ├── replay.ts             # Run replay from log
│   │   │   ├── migrations/
│   │   │   │   └── 001-init.sql
│   │   │   └── index.ts
│   │   ├── __tests__/
│   │   │   ├── store.test.ts
│   │   │   └── hash-chain.test.ts
│   │   ├── package.json
│   │   └── tsconfig.json
│   │
│   ├── tool-executors/                # Tool class implementations
│   │   ├── src/
│   │   │   ├── base.ts               # ToolExecutor interface
│   │   │   ├── http.ts               # HTTP/API executor
│   │   │   ├── file.ts               # File read/write executor
│   │   │   ├── shell.ts              # Shell command executor
│   │   │   ├── database.ts           # Database query executor
│   │   │   ├── registry.ts           # Executor registry
│   │   │   └── index.ts
│   │   ├── __tests__/
│   │   │   ├── http.test.ts
│   │   │   ├── file.test.ts
│   │   │   ├── shell.test.ts
│   │   │   └── database.test.ts
│   │   ├── package.json
│   │   └── tsconfig.json
│   │
│   ├── runtime/                       # Main orchestrator
│   │   ├── src/
│   │   │   ├── firewall.ts           # createFirewall(), Firewall class
│   │   │   ├── pipeline.ts           # Intercept pipeline
│   │   │   ├── config.ts             # Runtime config loading
│   │   │   ├── hooks.ts              # Lifecycle hooks (onDecision, onExecute, etc.)
│   │   │   └── index.ts
│   │   ├── __tests__/
│   │   │   ├── firewall.test.ts
│   │   │   └── pipeline.test.ts
│   │   ├── package.json
│   │   └── tsconfig.json
│   │
│   └── attack-sim/                    # Attack simulation pack
│       ├── src/
│       │   ├── runner.ts              # Simulation runner
│       │   ├── scenarios/
│       │   │   ├── prompt-injection.ts
│       │   │   ├── tool-misuse.ts
│       │   │   ├── data-exfiltration.ts
│       │   │   └── privilege-escalation.ts
│       │   ├── report.ts             # Simulation report generator
│       │   └── index.ts
│       ├── __tests__/
│       │   └── runner.test.ts
│       ├── package.json
│       └── tsconfig.json
│
├── apps/
│   └── cli/                           # CLI application
│       ├── src/
│       │   ├── main.ts               # Entry point
│       │   ├── commands/
│       │   │   ├── run.ts            # Run agent with firewall
│       │   │   ├── replay.ts         # Replay audit log
│       │   │   ├── simulate.ts       # Run attack simulations
│       │   │   ├── policy.ts         # Validate/lint policies
│       │   │   └── init.ts           # Init config in a project
│       │   └── output.ts            # Terminal output formatting
│       ├── package.json
│       └── tsconfig.json
│
├── policies/
│   ├── deny-all.yaml                  # Base deny-all policy
│   ├── safe-defaults.yaml             # Sensible starter policy
│   └── examples/
│       ├── web-researcher.yaml        # Example: agent that can fetch URLs
│       └── code-assistant.yaml        # Example: agent that can read/write files
│
├── turbo.json
├── pnpm-workspace.yaml
├── tsconfig.base.json
├── biome.json
├── package.json
└── LICENSE                            # Apache 2.0
```

---

## 4. Core Domain Model

### Principal (the agent identity)

```typescript
// packages/core/src/types/principal.ts

type ToolClass = 'http' | 'file' | 'shell' | 'database' | 'browser';

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
// packages/core/src/types/tool-call.ts

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
// packages/core/src/types/taint.ts

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
// packages/core/src/types/policy.ts

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
  tags?: string[];                       // for organization, e.g. ['security', 'compliance']
}

interface PolicySet {
  name: string;
  version: string;
  rules: PolicyRule[];
}

interface Decision {
  verdict: DecisionVerdict;
  matchedRule: PolicyRule | null;         // null = matched the implicit deny-all
  reason: string;
  taintLabels: TaintLabel[];
  timestamp: string;
}
```

### AuditEvent (the immutable record)

```typescript
// packages/core/src/types/audit.ts

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

interface RunContext {
  runId: string;
  principalId: string;
  startedAt: string;
  endedAt?: string;
  eventCount: number;
  config: FirewallConfig;                // snapshot of config at run start
}
```

---

## 5. Services/Modules and Responsibilities

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
- Exposes the public API: createFirewall()
```

---

## 6. Audit Event Schema (SQLite)

```sql
-- packages/audit-log/src/migrations/001-init.sql

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
2. Project policies (priority 100-899)       -- from agent-firewall.policy.yaml
3. Runtime overrides (priority 900-999)      -- passed programmatically
```

Lower priority number = evaluated first. First match wins.

**Policy YAML format:**

```yaml
# agent-firewall.policy.yaml
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
Agent calls: firewall.execute({ toolClass: 'http', action: 'get', parameters: { url: '...' } })
       |
       v
  1. VALIDATE
     - Parse + validate ToolCall via Zod
     - Assign ID, timestamp, sequence
       |
       v
  2. COLLECT TAINT
     - TaintTracker.collectInputTaints()
     - Attach any new taints from params
       |
       v
  3. EVALUATE POLICY
     - Check capability grants
     - Check constraints
     - Evaluate policy rules
     - Return Decision
       |
       v
  4. ENFORCE DECISION
     - DENY: log + throw DeniedError
     - REQUIRE-APPROVAL: call approval handler, block until resolved
     - ALLOW: continue to execution
       |
       v
  5. EXECUTE
     - Route to correct ToolExecutor
     - Execute with timeout + limits
     - Capture result or error
       |
       v
  6. PROPAGATE TAINT
     - Apply input taints to output
     - Add tool-output taint
       |
       v
  7. AUDIT LOG
     - Create AuditEvent
     - Compute hash chain
     - Append to SQLite
       |
       v
  Return ToolResult to agent
```

**Public API surface:**

```typescript
import { createFirewall } from '@agent-firewall/runtime';

const firewall = createFirewall({
  principal: {
    name: 'my-agent',
    capabilities: [
      { toolClass: 'http', actions: ['get'], constraints: { allowedHosts: ['api.github.com'] } },
      { toolClass: 'file', actions: ['read'], constraints: { allowedPaths: ['./data/**'] } },
    ],
  },
  policies: './agent-firewall.policy.yaml',
  auditLog: './audit.db',
  onApprovalRequired: async (toolCall, decision) => {
    return prompt(`Allow ${toolCall.action} on ${toolCall.toolClass}? (y/n)`);
  },
});

// Intercept a tool call
const result = await firewall.execute({
  toolClass: 'http',
  action: 'get',
  parameters: { url: 'https://api.github.com/repos/...' },
  taintLabels: [],
});

// Replay a run
const events = await firewall.replay(runId);

// Shutdown
await firewall.close();
```

---

## 10. MVP Scope vs. Later

### MVP (build now)

- Core types + Zod schemas
- PolicyEngine with YAML loading, rule matching, deny-by-default
- TaintTracker with attach, propagate, query
- AuditStore with SQLite, hash chain, basic query
- ToolExecutors: HTTP, File, Shell, Database (basic)
- Runtime orchestrator with intercept pipeline
- CLI: `init`, `run`, `replay`, `simulate`, `policy validate`
- Attack simulation: prompt injection, tool misuse, data exfil, privilege escalation
- Default policy packs: deny-all, safe-defaults
- Audit log replay from CLI
- Apache 2.0 license

### Later (post-MVP)

- Web dashboard for audit exploration
- Hosted control plane (SaaS)
- Enterprise policy management (RBAC, policy versioning, approval workflows)
- SIEM export (Splunk, Datadog, Sentinel)
- Browser tool executor (Playwright-based)
- Multi-agent support (agent-to-agent calls through firewall)
- Slack/email approval workflows
- Policy-as-code CI integration
- SDK wrappers for Python agents (LangChain, CrewAI, etc.)
- Encrypted audit logs

### Not recommended

- Custom policy DSL -- YAML is enough
- ML-based policy decisions -- rule-based is predictable and auditable
- GraphQL API -- REST is simpler and sufficient
- Microservices architecture -- this is a library, not a distributed system
- Kubernetes/Docker in MVP -- ship an npm package, not infra
- Plugin marketplace -- premature; just expose hooks

---

## 11. 12-Week Implementation Roadmap

### Weeks 1-2: Foundation
- Monorepo scaffold (pnpm, Turborepo, tsconfig, Biome)
- `@agent-firewall/core` -- all types, Zod schemas, ID generation, error classes
- CI: GitHub Actions for lint + test + build

### Weeks 3-4: Policy Engine
- `@agent-firewall/policy-engine` -- YAML loader, rule validation, matcher, evaluation
- Default policy packs (deny-all, safe-defaults)
- Thorough unit tests for matcher edge cases

### Weeks 5-6: Taint Tracker + Audit Log
- `@agent-firewall/taint-tracker` -- label management, propagation, queries
- `@agent-firewall/audit-log` -- SQLite store, hash chain, migrations, replay

### Weeks 7-8: Tool Executors
- `@agent-firewall/tool-executors` -- HTTP, File, Shell, Database
- Executor registry, base interface, timeout/limit enforcement
- Integration tests for each executor

### Weeks 9-10: Runtime + CLI
- `@agent-firewall/runtime` -- Firewall class, pipeline, config, hooks
- `@agent-firewall/cli` -- init, run, replay, policy validate
- End-to-end integration tests

### Weeks 11-12: Attack Sim + Polish
- `@agent-firewall/attack-sim` -- scenario runner, report generator
- Example agents + policy files
- Documentation, getting-started guide
- npm publish dry run, package.json metadata
- Performance baseline (1000 tool calls/sec target)

---

## 12. Risks, Tradeoffs, and What NOT to Over-Engineer

### Risks

| Risk | Mitigation |
|------|------------|
| Performance overhead of synchronous intercept | Benchmark early. PolicyEngine should be <1ms per evaluation. |
| Policy rules too rigid for real-world use | Start simple, add matchers incrementally. Hooks provide escape hatch. |
| Taint tracking too coarse | MVP tracks at ToolCall level, not field level. Good enough to start. |
| SQLite won't scale for hosted/multi-tenant | Correct. SQLite is for local runtime. Hosted version gets Postgres later. |
| Nobody wants to write YAML policies | Ship good defaults + `init` command that generates starter policy. |

### Key tradeoffs

1. **Library-first, not server-first** -- Lower adoption friction
2. **Synchronous intercept, not async** -- Simpler mental model
3. **SQLite, not Postgres** -- Zero infra dependency
4. **YAML policies, not code policies** -- Declarative, diffable, non-dev-accessible
5. **ToolCall-level taint, not field-level** -- Covers 90% of cases with 10% complexity

### Do NOT over-engineer

- Do not build a policy versioning system -- Git is the version control
- Do not build multi-tenant isolation -- Single principal per instance is fine
- Do not build a plugin system -- Hooks + direct code is enough
- Do not build field-level taint tracking -- ToolCall-level is sufficient
- Do not build a web UI -- CLI + JSON output is enough
- Do not abstract the storage layer -- Just use SQLite directly
- Do not support multiple policy formats -- YAML only

---

## Build Order: Steps 1-15

| Step | What | Package | Depends On |
|------|------|---------|------------|
| 1 | Monorepo scaffold: pnpm, Turborepo, tsconfig, Biome, Vitest, CI | root | -- |
| 2 | Core types: Principal, ToolCall, TaintLabel, PolicyRule, Decision, AuditEvent | `core` | 1 |
| 3 | Zod schemas for all core types + config | `core` | 2 |
| 4 | ID generation (ULID) + typed error classes | `core` | 2 |
| 5 | Policy matcher: rule-to-toolcall matching logic | `policy-engine` | 3 |
| 6 | Policy loader: YAML parse + validate + merge layers | `policy-engine` | 5 |
| 7 | Policy engine: evaluate() with priority ordering + deny-by-default | `policy-engine` | 6 |
| 8 | Taint tracker: attach, propagate, query, merge | `taint-tracker` | 3 |
| 9 | Audit store: SQLite schema, append, hash chain, verify | `audit-log` | 3 |
| 10 | Audit replay: reconstruct run from events | `audit-log` | 9 |
| 11 | Tool executors: base interface + HTTP, File, Shell, Database | `tool-executors` | 3 |
| 12 | Runtime: Firewall class, intercept pipeline, config, hooks | `runtime` | 7, 8, 9, 11 |
| 13 | CLI: init, run, replay, policy validate | `cli` | 12 |
| 14 | Attack simulation: scenario runner + 4 scenario types + report | `attack-sim` | 12 |
| 15 | Default policies, example agents, packaging, publish prep | root | 13, 14 |

**Critical path: 1 -> 2 -> 3 -> 5 -> 6 -> 7 -> 12 -> 13**

Steps 8, 9, 10, 11 can be parallelized after step 3. Step 14 can be parallelized with step 13.
