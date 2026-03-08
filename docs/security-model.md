# Security Model

Ari Kernel enforces security at the tool execution boundary — between an AI agent's decision to invoke a tool and the tool's actual execution. This document describes the four enforcement layers and how they compose.

## Capability Tokens

Agents do not receive ambient tool access. Every protected tool call requires a **capability token** — a short-lived grant scoped to a specific tool class and action.

- **Time-limited**: default TTL of 5 minutes
- **Usage-limited**: default lease of 10 calls
- **Scope-bound**: a token for `file.read` does not grant `file.write`
- **Constraint-enforced**: tokens carry constraints (allowed hosts, paths, commands) checked at execution time
- **Principal-bound**: a token issued to Agent A cannot be used by Agent B

If the agent does not hold a valid token, the call is denied before reaching the tool.

## Taint and Provenance Tracking

Tool call inputs and outputs carry **taint labels** indicating data provenance.

| Source | Label | Applied by |
|--------|-------|-----------|
| HTTP response | `web:<hostname>` | Auto-taint (HttpExecutor) |
| RAG retrieval | `rag:<source>` | Auto-taint (RetrievalExecutor) |
| MCP tool output | `web:<host>` / `rag:<source>` / `tool-output:mcp` | Auto-taint (McpDispatchExecutor) |
| Email content | `email` | Manual label |

Taint propagates forward: if a tool call's output is used as input to a subsequent call, the downstream call inherits upstream taint labels. Policies can condition on taint — for example, deny `shell.exec` when the call carries a `web` taint label.

Auto-taint from HTTP and RAG executors is applied automatically. No manual labeling required for common data sources.

## Behavioral Sequence Detection

A **sliding event window** (last 20 events) tracks normalized security events across the run. Three built-in rules evaluate patterns in real time:

### `web_taint_sensitive_probe`

**Pattern**: `taint_observed(web)` → `sensitive_read_attempt`

**Detects**: Prompt injection causing an agent to read secrets after processing untrusted web content.

### `denied_capability_then_escalation`

**Pattern**: `capability_denied` → `capability_requested(higher risk)`

**Detects**: Automated privilege escalation — an agent probing for capabilities after being denied. Tool classes have a risk ordering: `http(1) < database(2) < file(3) < shell(5)`.

### `sensitive_read_then_egress`

**Pattern**: `sensitive_read_attempt` → `egress_attempt`

**Detects**: Data staging followed by exfiltration — reading credentials or secrets, then attempting an outbound HTTP write.

Rules fire on the first match. The system does not wait for threshold counters.

## Run-Level Quarantine

When a behavioral rule matches — or when denial counters exceed a configurable threshold — the run enters **restricted mode**.

In restricted mode:
- Only read-only safe actions are allowed (`http.get`, `file.read`, `database.query`)
- Write, execute, and escalation attempts are denied for the remainder of the session
- Quarantine is immediate and irrecoverable within the run

The design principle is containment: a compromised agent session should be isolated, not rehabilitated.

Quarantine produces a `QuarantineInfo` record containing:
- Trigger type (`behavioral_rule` or `threshold`)
- Rule ID that matched
- Human-readable reason
- Counters snapshot at time of quarantine
- Matched events that formed the pattern

## Tamper-Evident Audit

Every decision — allow, deny, quarantine — is recorded in a **SHA-256 hash-chained event store**. Each event's hash includes the hash of the previous event, forming a tamper-evident chain.

Any modification, deletion, or insertion of events breaks the chain and is detected on replay.

```bash
arikernel trace --latest     # view the security trace
arikernel replay --latest    # replay and verify the hash chain
```

Quarantine events are first-class audit records with structured metadata. The audit trail answers not just "what happened" but "why the system responded this way."

## What Ari Kernel Does NOT Do

- **Prompt filtering** — it does not inspect model input/output text
- **Jailbreak detection** — it does not classify prompt attacks
- **Content moderation** — it does not filter harmful text output
- **Model-level safety** — it does not address training data poisoning or adversarial inputs

Ari Kernel operates at the tool-call layer. It is complementary to prompt-level defenses, not a replacement. The stronger story: even if prompt injection succeeds, the agent cannot execute dangerous actions because ARI enforces the execution boundary.
