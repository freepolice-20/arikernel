# Reference Monitor Specification

A formal description of Ari Kernel's enforcement architecture for security researchers and auditors.

> See also: [Agent Reference Monitor](agent-reference-monitor.md) (design rationale) | [Security Model](security-model.md) (enforcement details) | [Threat Model](threat-model.md) (attack scenarios) | [Architecture](../ARCHITECTURE.md) (implementation)

---

## 1. Introduction

AI agents execute side-effectful operations — HTTP requests, file I/O, shell commands, database queries — through tool calls. In standard deployments, the agent runtime grants ambient authority: every tool call executes with the full permissions of the host process. There is no enforcement boundary between the model's decision to invoke a tool and the tool's execution.

This creates a structural vulnerability. Prompt injection, tainted retrieval data, and adversarial email content can manipulate the agent's reasoning. Without an enforcement boundary, manipulated reasoning leads directly to manipulated execution. The attack surface is not the model — it is the absence of mediation between reasoning and action.

Ari Kernel is a runtime enforcement layer that interposes on every tool call an agent makes. It evaluates capability grants, data provenance, policy rules, and behavioral patterns before permitting execution. This document specifies how Ari Kernel approaches the properties of a reference monitor for AI agent tool execution, and where the current implementation falls short of the classical model.

---

## 2. Reference Monitor Model

Anderson (1972) defined three properties required for a trusted enforcement boundary:

| Property | Definition | Ari Kernel Mapping |
|----------|------------|--------------------|
| **Complete mediation** | Every access request passes through the monitor. No bypass path exists. | Tool calls routed through the kernel pass through `Pipeline.intercept()`. In sidecar mode, no direct agent→tool path exists within the process boundary. In embedded mode, mediation is cooperative — the framework must route all calls through the kernel (see §8.2). |
| **Tamper resistance** | The monitor's enforcement logic cannot be modified by the subjects it governs. | The LLM cannot modify policy rules, taint state, behavioral counters, or the audit log — these are runtime objects outside its control. In sidecar mode, these are in a separate process (hardware-isolated from the agent). In embedded mode, they share the agent's address space (see §8.3). |
| **Verifiability** | The monitor is small enough to be subjected to analysis and testing. | The enforcement pipeline is a bounded, linear sequence of seven stages (§3). Each stage has defined inputs, outputs, and invariants. The pipeline is deterministic for a given input and state. |

### Qualification

Ari Kernel is a **userspace reference monitor**. It does not operate at the OS kernel or hypervisor level. The complete mediation property holds when all tool execution is routed through the kernel — either by application-level integration (embedded mode) or by process-boundary enforcement (sidecar mode). Code that bypasses the kernel by invoking OS APIs directly is not mediated. See §8 for a full discussion of limitations.

---

## 3. Enforcement Boundary

### 3.1 Pipeline Architecture

```
┌──────────────────────────────────────────┐
│              Agent Runtime               │
│  (LLM, framework, application code)      │
└────────────────────┬─────────────────────┘
                     │ ToolCallRequest
                     │ {toolClass, action, parameters, taintLabels, grantId?}
                     ▼
┌──────────────────────────────────────────┐
│         Ari Kernel — Enforcement         │
│                                          │
│  Stage 1    Schema validation            │
│  Stage 1.5  Run-state restriction check  │
│             Security event tracking      │
│             Capability token enforcement │
│  Stage 2    Taint collection             │
│  Stage 3    Policy evaluation            │
│  Stage 4    Decision enforcement         │
│  ─ ─ ─ ─ ─ execution boundary ─ ─ ─ ─ ─ │
│  Stage 5    Tool execution               │
│  Stage 6    Taint propagation            │
│             Output filtering (DLP)       │
│  Stage 6.5  Behavioral rule check        │
│  Stage 7    Audit log append             │
│                                          │
│  State:                                  │
│    Principal    (identity + capabilities) │
│    TokenStore   (active grants)          │
│    TaintState   (run-level taint)        │
│    RunState     (counters, event window) │
│    AuditStore   (hash-chained events)    │
└────────────────────┬─────────────────────┘
                     │ ToolResult | ToolCallDeniedError
                     ▼
┌──────────────────────────────────────────┐
│           Tool Executors                 │
│  HTTP │ File │ Shell │ Database │ MCP    │
│  (registered, not directly accessible)   │
└──────────────────────────────────────────┘
```

### 3.2 Mediation Invariant

Every tool execution satisfies the following:

```
∀ tool_call T:
  T reaches an executor ⟹ T passed through Pipeline.intercept()
  Pipeline.intercept(T) returned "allow" ⟹ all of:
    1. T.schema is valid
    2. T is permitted under current run-state
    3. T holds a valid capability token (for protected actions)
    4. T satisfies the principal's base capabilities
    5. T satisfies all matching policy rules
    6. No behavioral rule triggered quarantine
```

The pipeline is **synchronous**. The agent blocks until the kernel returns a decision. There is no asynchronous path that permits execution before evaluation completes.

### 3.3 Deny-by-Default

If no policy rule explicitly matches a tool call, the default decision is `deny`. Unknown tool classes, unknown actions, and unrecognized capability classes are all treated as writes and denied. This is a fail-closed design.

---

## 4. Capability Enforcement

### 4.1 Principal Model

A **principal** represents an agent identity with explicitly granted capabilities:

```
Principal := {
  id:           UniqueId
  name:         String
  capabilities: [Capability]
  parentId?:    UniqueId          // set when capabilities were delegated
}

Capability := {
  toolClass:    ToolClass         // http | file | shell | database | browser | retrieval | mcp
  actions?:     [String]          // e.g. ["get", "head"]. Absent = all actions.
  constraints?: CapabilityConstraints
}

CapabilityConstraints := {
  allowedPaths?:       [String]   // filesystem path prefixes
  allowedHosts?:       [String]   // hostname allowlist
  allowedCommands?:    [String]   // shell command allowlist
  allowedDatabases?:   [String]   // database name allowlist
  maxCallsPerMinute?:  Number     // rate limit
}
```

There is no ambient authority. A principal without a `shell` capability cannot execute shell commands regardless of policy rules.

### 4.2 Capability Tokens

Protected actions require a **capability token** — a short-lived grant obtained through `requestCapability()`:

```
CapabilityGrant := {
  id:              UniqueId
  principalId:     UniqueId
  capabilityClass: CapabilityClass    // e.g. "http.read", "shell.exec", "file.write"
  constraints:     CapabilityConstraint
  lease:           { issuedAt, expiresAt, maxCalls, callsUsed }
  taintContext:    [TaintLabel]
  revoked:         Boolean
}
```

Token properties:
- **Time-bounded**: default TTL of 5 minutes
- **Usage-bounded**: default lease of 10 calls
- **Scope-bound**: a token for `file.read` does not grant `file.write`
- **Principal-bound**: tokens are validated against the requesting principal
- **Atomically consumed**: the `TokenStore.consume()` method validates and increments the call counter in a single operation, preventing time-of-check-to-time-of-use (TOCTOU) races

Token validation occurs at execution time (Stage 1.5), not only at issuance. A token that expires or is revoked between issuance and use is rejected.

### 4.3 Issuance Evaluation

Capability issuance is a five-step evaluation:

1. **Base capability check** — the principal must hold the tool class in its capabilities
2. **Action check** — at least one of the token's actions must be permitted by the base capability
3. **Taint risk assessment** — untrusted taint sources (`web`, `rag`, `email`, `retrieved-doc`) block sensitive capability classes (`shell.exec`, `database.read`, `database.write`, `file.write`)
4. **Policy evaluation** — a synthetic tool call is evaluated against the policy rule set
5. **Constraint intersection** — requested constraints are intersected with base capability constraints. The grant can only narrow, never broaden, the base capability

### 4.4 Capability Delegation

When multiple agents cooperate (planner, browser, scraper), a parent agent can delegate capabilities to sub-agents. The delegation model enforces monotonic narrowing:

```
effective_capability = parent_capability ∩ child_request
```

For each field:
- **Actions**: set intersection. Child receives only actions the parent holds.
- **Constraints** (paths, hosts, commands, databases): set intersection per field. Child receives only values present in both sets.
- **Rate limits**: `min(parent, child)`. The stricter limit applies.

Delegation metadata records provenance:

```
DelegationMetadata := {
  issuedBy:         PrincipalId
  delegatedTo:      PrincipalId
  delegationChain:  [PrincipalId]   // ordered, root to current holder
  delegatedAt:      Timestamp
}
```

Properties:
- **Multi-hop composition**: A→B→C produces chain `[A, B, C]`, each hop further narrowing
- **Transitive revocation**: revoking B invalidates both B's and C's delegated capabilities
- **Backward compatible**: principals without delegation metadata function identically to the single-principal model

---

## 5. Taint Tracking

### 5.1 Taint Model

Every tool call input and output can carry **taint labels** indicating data provenance:

```
TaintLabel := {
  source:          TaintSource    // web | rag | email | retrieved-doc | model-generated |
                                  // user-provided | tool-output
  origin:          String         // e.g. "example.com", "customer_docs", tool call ID
  confidence:      Float [0, 1]
  addedAt:         Timestamp
  propagatedFrom?: ToolCallId     // set when taint propagated from a prior call
}
```

### 5.2 Automatic Taint Application

Specialized executors apply taint labels automatically at tool boundaries:

| Executor | Taint source | Origin | Trigger |
|----------|-------------|--------|---------|
| HTTP | `web` | Request hostname | Every response (success or error) |
| Retrieval / RAG | `rag` | Source identifier | Every retrieval result |
| MCP | `web` / `rag` / `tool-output` | MCP server host | Every MCP tool invocation |

Auto-taint is applied unconditionally. The agent cannot suppress or remove taint labels applied by executors.

### 5.3 Taint Propagation

Taint propagates forward through tool call chains:

```
T₁ output has labels L₁
T₂ uses T₁ output as input
⟹ T₂ carries L₁ (with propagatedFrom = T₁.id)
   T₂ output carries L₁ ∪ L₂ (where L₂ is T₂'s own auto-taint)
```

### 5.4 Run-Level Taint Stickiness

The kernel maintains **run-level taint state** independently of individual tool calls:

```
TaintState := {
  tainted:  Boolean    // sticky — once true, never resets
  sources:  Set<TaintSource>
  labels:   [TaintLabel]
}
```

Run-level taint is monotonically accumulating. A tool cannot clear the run's taint state. This prevents an attack where a compromised agent drops taint labels between calls to evade provenance-based policies.

### 5.5 Taint-Conditioned Policy

Policy rules can match on taint sources:

```yaml
- id: deny-shell-on-web-taint
  match:
    toolClass: shell
    taintSources: [web, rag, email]
  decision: deny
  reason: "Shell execution denied: untrusted data in provenance chain"
```

The combination of automatic taint application, forward propagation, run-level stickiness, and taint-conditioned policy creates a provenance-aware enforcement model. The kernel evaluates not only what the agent is doing, but where the data driving the action came from.

---

## 6. Behavioral Detection

### 6.1 Event Window

The kernel maintains a sliding window of the most recent 20 normalized security events:

```
SecurityEvent := {
  timestamp:  Timestamp
  type:       EventType    // taint_observed | sensitive_read_attempt |
                           // egress_attempt | capability_denied |
                           // capability_granted | tool_call_allowed | ...
  toolClass:  ToolClass
  metadata:   Record
}
```

Events are generated at multiple pipeline stages:
- Taint observation (Stage 2)
- HTTP egress detection (Stage 1.5)
- Sensitive file access (Stage 1.5)
- Capability request/grant/denial (issuance path)
- Shell and database operations (Stage 1.5)

### 6.2 Behavioral Rules

Six built-in rules evaluate sequential patterns in the event window:

| Rule ID | Pattern | Attack Class |
|---------|---------|-------------|
| `web_taint_sensitive_probe` | taint_observed(web/rag/email) → sensitive_read / shell / egress | Prompt injection → data access |
| `denied_capability_then_escalation` | capability_denied → capability_requested(higher risk) | Privilege escalation probing |
| `sensitive_read_then_egress` | sensitive_read_attempt → egress_attempt | Data staging → exfiltration |
| `tainted_database_write` | taint_observed(web/rag/email) → database write/exec/mutate | Tainted SQL injection |
| `tainted_shell_with_data` | taint_observed(web/rag/email) → shell exec (command >100 chars) | Shell-based data exfiltration |
| `secret_access_then_any_egress` | secret/credential access → any egress | Credential theft |

Rules evaluate after every security event. The first match triggers immediately. The system does not batch or defer evaluation.

### 6.3 Quarantine

When a behavioral rule matches — or when denial counters exceed a configurable threshold (default: 5 denied sensitive actions) — the run enters **restricted mode**:

- Read-only actions are permitted: `file.read`, `database.query`, `http.get`, `http.head`
- All write, execute, and escalation actions are denied
- Suspicious GET-based exfiltration (query strings >256 chars, parameters >128 chars) is blocked
- The triggering action itself is denied (no first-hit exfiltration)
- Quarantine is **immediate** and **irrecoverable** within the run

```
QuarantineInfo := {
  triggerType:       "behavioral_rule" | "threshold"
  ruleId:            String
  reason:            String
  countersSnapshot:  RunStateCounters
  matchedEvents:     [SecurityEvent]
}
```

The design principle is containment, not rehabilitation. A session exhibiting adversarial behavioral patterns is locked down. The agent cannot retry, escalate, or pivot to alternative attack paths.

---

## 7. Deployment Modes

### 7.1 Embedded Mode

```
┌─────────────────────────────────┐
│         Host Process            │
│                                 │
│  ┌─────────┐   ┌────────────┐  │
│  │  Agent   │──▶│ Ari Kernel │  │
│  └─────────┘   └─────┬──────┘  │
│                       │         │
│                ┌──────▼──────┐  │
│                │  Executors  │  │
│                └─────────────┘  │
└─────────────────────────────────┘
```

The kernel runs as a library in the same process as the agent. Tool calls are intercepted via `firewall.execute()` or framework adapter wrappers.

**Mediation strength**: cooperative. Enforcement depends on the application routing all tool calls through the kernel. Code that invokes OS APIs directly (e.g., `fetch()`, `child_process`) bypasses enforcement.

**Tamper resistance**: limited. The agent process can theoretically inspect the kernel's in-memory state (token store, taint state). In practice, LLM agents do not have arbitrary code execution within the host process, but the isolation boundary is the process, not a hardware or OS-level boundary.

**Use case**: development, testing, trusted agent integration, single-process prototyping.

### 7.2 Sidecar Mode

```
┌──────────────┐          ┌──────────────────────────┐
│ Host Process  │   HTTP   │   Sidecar Process        │
│              │          │                          │
│  ┌────────┐  │  ──────▶ │  ┌────────────────────┐  │
│  │ Agent  │  │          │  │    Ari Kernel       │  │
│  └────────┘  │  ◀────── │  │  (full pipeline)    │  │
│              │          │  └─────────┬──────────┘  │
└──────────────┘          │            │             │
                          │     ┌──────▼──────┐      │
                          │     │  Executors  │      │
                          │     └─────────────┘      │
                          └──────────────────────────┘
```

The kernel runs as a separate HTTP proxy process. The agent communicates with it over authenticated HTTP.

**Mediation strength**: stronger. No code path from agent to tools exists within the agent's process. All side-effectful operations are mediated by the sidecar. The optional **sidecar guard** intercepts `fetch()` and `child_process` in the host process to catch accidental bypass.

**Tamper resistance**: stronger. The token store, policy engine, taint state, and audit log reside in a separate process. The agent cannot inspect or modify enforcement state.

**Use case**: production deployments, untrusted agents, compliance-sensitive environments.

### 7.3 Comparison

| Property | Embedded | Sidecar |
|----------|----------|---------|
| Complete mediation | Cooperative (app-level routing) | Process boundary (+ optional guard) |
| Tamper resistance | In-process (agent can inspect memory) | Separate process (agent cannot access) |
| Audit isolation | In-process | Separate process |
| Token store isolation | In-process | Separate process |
| Taint tracking | Full auto-taint | Full auto-taint |
| Latency | Microseconds | Milliseconds (HTTP round-trip) |
| Language support | TypeScript only | Any language (HTTP client) |

Sidecar is the highest-assurance deployment mode when all side-effectful operations are routed through it and the host application does not retain ambient authority to invoke tools outside the mediated path.

---

## 8. Limitations

This section enumerates what Ari Kernel does **not** provide. Security assessments should account for these boundaries.

### 8.1 Not OS-Level Mediation

Ari Kernel is a userspace enforcement layer. It does not intercept syscalls, control network namespaces, or enforce filesystem permissions at the kernel level. An agent with access to raw Node.js APIs (`net.Socket`, `fs.writeFileSync`, `child_process.spawn`) can bypass enforcement if those APIs are not routed through the kernel.

**Mitigation**: In sidecar mode, the optional sidecar guard intercepts `fetch()` and `child_process` to catch accidental bypass. For intentional bypass resistance, combine with OS-level controls (seccomp, AppArmor, network policies).

### 8.2 Routing Dependency

The complete mediation property depends on tool execution being routed through the kernel. In embedded mode, this is enforced by application design. In middleware mode, this depends on the framework correctly wrapping all tools. Any tool call that reaches an executor without passing through the pipeline is unmediated.

### 8.3 In-Process Isolation Limits

In embedded mode, the enforcement state (token store, taint state, policy rules) resides in the same process as the agent. A sufficiently capable agent with arbitrary code execution could theoretically inspect or modify this state. LLM agents typically do not have this capability, but the isolation boundary is cooperative, not hardware-enforced.

### 8.4 No Content Inspection

Ari Kernel evaluates structured tool call metadata (tool class, action, parameters, taint labels). It does not inspect the semantic content of tool call inputs or outputs. It cannot detect prompt injection in text, identify PII in response bodies, or classify harmful content. It is complementary to, not a replacement for, content-level defenses.

### 8.5 Limited Multi-Agent Collusion Detection

Each principal is evaluated independently. The sidecar provides lightweight cross-principal provenance via the `SharedTaintRegistry` (marks shared resources contaminated when a tainted principal writes) and `CrossPrincipalCorrelator` (alerts on three cross-principal patterns):

- **CP-1** (High): Principal A reads sensitive file → writes shared store resource X → Principal B reads resource X → Principal B egresses. Resource-key aware — the write and read must target the same canonical resource.
- **CP-2** (Medium): Any principal with `derived-sensitive` taint attempts HTTP write egress.
- **CP-3** (High): Multiple principals egress to the same destination host within the correlation window, and at least one had a recent sensitive file read. Catches out-of-band relay attacks where Agent A posts secrets to a relay host and Agent B fetches from the same relay then exfiltrates elsewhere — without any shared-store involvement.

**Quarantine-on-alert**: Setting `quarantineOnAlert: true` in the correlator config escalates CP alerts from detection to enforcement — all principals named in a CP alert are immediately quarantined via `Firewall.quarantineExternal()`. This ensures that once a tag-team attack is detected, both the sender and receiver are locked down.

However, cross-principal correlation is alerting and provenance tracking, not full information-flow control. Agents coordinating via channels not visible to the kernel (e.g., shared memory, timing side-channels, steganography in allowed outputs) are not detected. Capability delegation (§4.4) addresses authorized multi-agent cooperation but does not detect adversarial collusion.

### 8.6 Audit Chain Limitations

The SHA-256 hash chain provides local tamper evidence — it detects post-hoc modifications to the log. It does not provide completeness guarantees (the entire database could be replaced), non-repudiation (events are not cryptographically signed with an external key), or integrity under full host compromise (an attacker with process access can recompute valid hashes).

### 8.7 DNS and Network-Level Attacks

Hostname-based allowlists are resolved at request time. DNS rebinding attacks (where an attacker controls resolution of an allowed hostname) are not fully mitigated. SSRF protection validates resolved IPs against private ranges, but dynamic DNS manipulation between validation and connection is a known gap.

---

## 9. Future Work

The following enhancements are under consideration or in progress:

### Sandboxed Executors

Run tool executors in isolated environments (V8 isolates, WASM sandboxes, container boundaries) to limit blast radius even when a tool call is permitted. Currently, executors run in the same trust domain as the kernel.

### OS-Level Mediation

Integration with OS-level enforcement (seccomp-bpf, Linux Security Modules, Windows Defender Application Control) to provide syscall-level mediation. This would close the bypass gap in embedded mode by making the mediation property non-cooperative.

### Formal Verification

Apply formal methods to verify key safety invariants:
- Capability narrowing monotonicity (delegation never widens)
- Taint stickiness (run-level taint never decreases)
- Quarantine irreversibility (restricted mode never reverts)
- Policy completeness (deny-by-default holds for all inputs)

### Multi-Agent Collusion Detection

Cross-principal behavioral analysis to detect coordinated attack patterns where individual principals operate within policy but the collective behavior is adversarial. The CP-3 egress-destination convergence rule (§8.5) is a first step. Planned additions:

- **CP-4: Unusual-host detection.** Build a per-principal baseline of normal egress destinations (e.g. `api.openai.com`, `stripe.com`, `slack.com`). Alert when a principal with recent sensitive reads suddenly contacts a host outside its baseline (e.g. `relay-91832.net`). This would catch relay attacks even without a second principal converging on the same host.
- Full cross-principal behavioral pattern analysis.
- Transitive HTTP taint propagation across principal boundaries.
- Integration with network-level isolation policies.

### Dynamic Policy Updates

Runtime policy modification with versioning, rollback, and audit trail integration. Currently policies are static after kernel initialization.

---

## References

- Anderson, J. P. (1972). *Computer Security Technology Planning Study*. ESD-TR-73-51, Vol. II. U.S. Air Force Electronic Systems Division.
- Dennis, J. B., & Van Horn, E. C. (1966). Programming semantics for multiprogrammed computations. *Communications of the ACM*, 9(3), 143–155.
- Saltzer, J. H., & Schroeder, M. D. (1975). The protection of information in computer systems. *Proceedings of the IEEE*, 63(9), 1278–1308.
