# Security Model

Ari Kernel enforces security at the tool execution boundary — between an AI agent's decision to invoke a tool and the tool's actual execution. This document describes the enforcement layers and how they compose.

> See also: [Threat Model](threat-model.md) | [Agent Reference Monitor](agent-reference-monitor.md) | [Architecture](../ARCHITECTURE.md)

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

A **sliding event window** (last 20 events) tracks normalized security events across the run. Six built-in rules evaluate patterns in real time:

### `web_taint_sensitive_probe`

**Pattern**: `taint_observed(web/rag/email)` → `sensitive_read_attempt` / `shell exec` / `egress_attempt`

**Detects**: Prompt injection causing an agent to access secrets or execute commands after processing untrusted content.

### `denied_capability_then_escalation`

**Pattern**: `capability_denied` → `capability_requested(higher risk)`

**Detects**: Automated privilege escalation — an agent probing for capabilities after being denied. Tool classes have a risk ordering: `http(1) < database(2) < file(3) < shell(5)`.

### `sensitive_read_then_egress`

**Pattern**: `sensitive_read_attempt` → `egress_attempt`

**Detects**: Data staging followed by exfiltration — reading credentials or secrets, then attempting an outbound HTTP write.

### `tainted_database_write`

**Pattern**: `taint_observed(web/rag/email)` → `database write/exec/mutate`

**Detects**: Tainted data being written to a database — prevents SQL injection from untrusted input.

### `tainted_shell_with_data`

**Pattern**: `taint_observed(web/rag/email)` → `shell exec with long command string (>100 chars)`

**Detects**: Data being piped or exfiltrated via shell command arguments after untrusted input.

### `secret_access_then_any_egress`

**Pattern**: `secret/credential resource access` → `any egress attempt`

**Detects**: Credential theft — accessing secrets tables, vault endpoints, or credential files, followed by any outbound communication.

Rules fire on the first match. The system does not wait for threshold counters.

## Run-Level Quarantine

When a behavioral rule matches — or when denial counters exceed a configurable threshold — the run enters **restricted mode**.

In restricted mode:
- Read-only actions are allowed: `file.read`, `database.query`, `http.get`, `http.head`
- HTTP GET/HEAD are treated as **ingress** (content fetch) and allowed for continued read-only operation
- Suspicious GET exfiltration (oversized query strings, large parameter values) is detected and blocked separately
- True egress methods (`http.post`, `http.put`, `http.patch`, `http.delete`) are blocked
- Write, execute, and shell attempts are denied for the remainder of the session
- The action that triggers quarantine is itself denied (no first-hit exfiltration)
- Quarantine is immediate and irrecoverable within the run

The design principle is containment: a compromised agent session should be isolated, not rehabilitated.

Quarantine produces a `QuarantineInfo` record containing:
- Trigger type (`behavioral_rule` or `threshold`)
- Rule ID that matched
- Human-readable reason
- Counters snapshot at time of quarantine
- Matched events that formed the pattern

## Session-Level Taint

Once an agent processes untrusted external data (web content, RAG retrieval, email), the run is marked as **persistently tainted**. This flag never resets within the run and can be used by policies and behavioral rules to make decisions based on the run's overall trust level.

## SSRF Protection

The HTTP executor validates all request destinations before connecting:

- **DNS resolution**: hostnames are resolved to IP addresses before the request is made
- **Private IP blocking**: requests to loopback (127.x), private (10.x, 172.16-31.x, 192.168.x), link-local (169.254.x), and IPv6 equivalents are blocked
- **Redirect validation**: each redirect hop is validated against the same SSRF rules — a redirect from a public host to a private IP is blocked
- **URL length limits**: URLs exceeding 2048 characters are rejected to prevent data exfiltration via oversized query strings

## Symlink Protection

File path allowlists use `realpathSync()` to resolve symlinks before comparison (CWE-59 mitigation). A symlink at `./data/link → /etc/shadow` will be resolved to `/etc/shadow` and correctly blocked by the path allowlist, even if `./data/**` is permitted.

## Tamper-Evident Audit

Every decision — allow, deny, quarantine — is recorded in a **SHA-256 hash-chained event store**. Each event's hash includes the hash of the previous event, forming a tamper-evident chain.

Any modification, deletion, or insertion of events breaks the chain and is detected on replay.

```bash
arikernel trace --latest     # view the security trace
arikernel replay --latest    # replay and verify the hash chain
```

Quarantine events are first-class audit records with structured metadata. The audit trail answers not just "what happened" but "why the system responded this way."

### Hash Chain Limitations

The hash chain provides **local tamper evidence** — it detects modifications to an existing log after the fact. It does **not** provide:

- **Completeness guarantee**: if the entire database is replaced, there is no external anchor to detect the swap. For production deployments, forward audit events to an external SIEM or append-only log store.
- **Integrity under host compromise**: if an attacker has write access to the SQLite database and the application, they can recompute valid hashes. The hash chain deters casual tampering, not a sophisticated attacker with full host access.
- **Non-repudiation**: events are not cryptographically signed with a private key. The chain proves internal consistency, not authorship.

For high-assurance deployments, we recommend streaming audit events to an external append-only store (e.g., AWS CloudTrail, a SIEM, or an immutable log service) in addition to the local hash-chained store.

## Output Filtering (DLP)

Ari Kernel provides an `onOutputFilter` hook for scanning tool results before they reach the agent. The built-in `createSecretPatternFilter()` detects common secret patterns (AWS keys, private keys, GitHub tokens, Bearer tokens) and replaces them with `[REDACTED]`. Custom filters can be supplied for production DLP needs.

## Execution Environment Hardening

For OS and container-level hardening recommendations (network segmentation, filesystem isolation, secrets management, runtime monitoring), see [Execution Hardening](execution-hardening.md).

## What Ari Kernel Does NOT Do

- **Prompt filtering** — it does not inspect model input/output text
- **Jailbreak detection** — it does not classify prompt attacks
- **Content moderation** — it does not filter harmful text output
- **Model-level safety** — it does not address training data poisoning or adversarial inputs

Ari Kernel operates at the tool-call layer. It is complementary to prompt-level defenses, not a replacement. The stronger story: even if prompt injection succeeds, the agent cannot execute dangerous actions because Ari Kernel enforces the execution boundary.
