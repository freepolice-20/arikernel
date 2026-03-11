# Ari Kernel — Threat Model

**Version**: 1.0
**Date**: 2026-03-10
**Audience**: Security engineers, red-teamers, auditors

> See also: [Security Model](security-model.md) (enforcement mechanisms) | [Reference Monitor](reference-monitor.md) (formal enforcement architecture) | [Architecture](../ARCHITECTURE.md) (implementation)

---

## Table of Contents

1. [Overview](#1-overview)
2. [Security Objectives](#2-security-objectives)
3. [Attacker Model](#3-attacker-model)
4. [Protected Assets](#4-protected-assets)
5. [Trust Boundaries](#5-trust-boundaries)
6. [In-Scope Attacks](#6-in-scope-attacks)
7. [Out-of-Scope / Non-Goals](#7-out-of-scope--non-goals)
8. [Assumptions](#8-assumptions)
9. [Residual Risks](#9-residual-risks)
10. [Recommended Deployment Profiles](#10-recommended-deployment-profiles)
11. [Relationship to Existing Docs](#11-relationship-to-existing-docs)

---

## 1. Overview

Ari Kernel is a runtime enforcement layer for AI agents. It interposes on tool calls — the boundary where an agent's decisions become real-world side effects — and enforces security policy before execution.

**Core assumption**: prompt injection may succeed. Ari Kernel does not attempt to prevent injection at the model layer. Instead, it prevents injected or compromised agents from causing unauthorized real-world side effects. The security goal is **containment at the tool execution boundary**, not prevention of compromise at the reasoning layer.

This document defines what Ari Kernel defends against, what it does not, and under what conditions its guarantees hold. Claims are scoped to the current implementation, not idealized future architecture.

---

## 2. Security Objectives

Ari Kernel aims to provide the following properties when all tool execution is routed through the kernel:

| Objective | Mechanism | Guarantee Level |
|-----------|-----------|-----------------|
| **Capability-scoped tool access** | Signed, time-limited, usage-limited capability tokens with principal binding | Strong — cryptographic enforcement in sidecar; cooperative in embedded |
| **Constraint narrowing** | Intersection semantics on delegation; constraints can only narrow, never broaden | Strong — enforced at issuance and consumption |
| **Taint-aware policy evaluation** | Kernel-maintained run-level taint state; auto-tainting from tool output; content scanning | Moderate — label-based, not byte-level; encoding tricks can evade content scanning |
| **Behavioral detection and quarantine** | Six sequence rules over a 20-event sliding window; irrecoverable quarantine on match | Moderate — heuristic; bounded window; no semantic understanding of intent |
| **Audit logging and deterministic replay** | SHA-256 hash-chained audit events; full pipeline replay | Local tamper evidence only; not tamper-proof under host compromise |
| **Stronger isolation in sidecar mode** | Separate process; authenticated HTTP; per-principal API key binding; rate limiting | Strong within process boundary; not equivalent to OS/kernel mediation |

None of these properties are unconditional. Each depends on assumptions listed in [§8](#8-assumptions).

---

## 3. Attacker Model

### 3.1 Prompt Injection Attacker

**Profile**: Controls web content, documents, RAG data, or email that enters the agent's context.
**Capability**: Can influence or fully control the agent's tool call sequence via prompt injection. Inherits the agent's granted capabilities — no more.
**Goal**: Exfiltrate data, execute unauthorized commands, pivot to internal systems, or abuse agent capabilities for attacker-controlled purposes.

This is the **primary attacker** Ari Kernel is designed to contain.

### 3.2 Malicious or Compromised Tool

**Profile**: A tool executor or MCP server that returns crafted output designed to influence downstream agent behavior.
**Capability**: Can inject taint, return misleading data, or attempt to exploit content parsing.
**Goal**: Trigger the agent to perform actions the tool operator intended but the agent's principal does not authorize.

Ari Kernel mitigates this via auto-tainting of tool output and content scanning, but cannot prevent all forms of data-level influence.

### 3.3 Attacker-Controlled Agent Logic

**Profile**: The agent's code itself is malicious or has been supply-chain compromised.
**Capability**: In embedded/middleware mode, has full process access. In sidecar mode, limited to the sidecar HTTP API.
**Goal**: Bypass enforcement, exfiltrate data, or escalate privileges.

In sidecar mode, Ari Kernel enforces policy across a process boundary. In embedded mode, a malicious agent can bypass the kernel by calling OS APIs directly — enforcement is cooperative.

### 3.4 Authenticated but Unauthorized Sidecar Client

**Profile**: Holds valid sidecar credentials but attempts to act outside authorized scope.
**Capability**: Can make authenticated API calls to the sidecar.
**Goal**: Spoof another principal's identity, escalate capabilities, or exhaust resources.

Mitigated by: API key → principalId binding (identity derived from credentials, not request body), capability token scoping, per-principal rate limiting, and admission control.

### 3.5 Operator Misconfiguration

**Profile**: A trusted administrator who writes overly permissive policies, grants excessive capabilities, or deploys without authentication.
**Capability**: Full configuration authority.
**Goal**: Unintentional — misconfiguration that weakens security posture.

Ari Kernel provides fail-closed defaults (deny-all base rule, bounded regex evaluation) and presets, but cannot prevent a determined operator from configuring insecure policies.

### 3.6 Resource Exhaustion / DoS Attacker

**Profile**: Sends high volumes of requests to the sidecar.
**Capability**: Network access to the sidecar endpoint.
**Goal**: Exhaust sidecar resources, prevent legitimate agents from operating.

Mitigated by: per-principal and global rate limiting, concurrent execution limits, firewall instance limits, and request body size caps (1 MB).

---

## 4. Protected Assets

| Asset | Protection Mechanism |
|-------|---------------------|
| **Filesystem secrets** (SSH keys, `.env`, credentials) | Path constraints (`allowedPaths`), symlink resolution (O_NOFOLLOW + fstat + realpath), sensitive path detection triggering behavioral rules |
| **API credentials** | Behavioral rule `secret_access_then_any_egress` detects credential access followed by egress; quarantine blocks exfiltration |
| **Internal network access** | Host constraints (`allowedHosts`), SSRF mitigation in HTTP executor (private IP blocking, redirect validation) |
| **Database contents** | Database constraints (`allowedDatabases`), taint-aware `tainted_database_write` rule blocks injection from untrusted input |
| **Outbound egress channels** | Capability scoping (separate read/write grants), behavioral rules detect staging-then-exfil patterns |
| **Audit integrity** | SHA-256 hash chain provides local tamper evidence; chain break detected on replay |
| **Policy integrity** | Policy loaded at initialization; no runtime API for agents to modify policy rules; sidecar mode process-isolates policy state |

---

## 5. Trust Boundaries

### 5.1 Middleware Mode

```
┌──────────────────────────────────────┐
│          Agent Process               │
│                                      │
│  Agent ──► Middleware ──► Kernel ──► Tool
│         (cooperative routing)        │
└──────────────────────────────────────┘
```

- **Mediation**: Cooperative. The middleware wraps framework tools; a direct `fetch()` or `fs.readFile()` bypasses enforcement.
- **Tamper resistance**: None. Kernel state shares the agent's address space.
- **Taint fidelity**: Partial. Stub executors derive taint from parameters (`autoTaint`), not from actual tool output. Content scanning is unavailable.
- **Use case**: Zero-architecture-change integration. Suitable for development, testing, and low-risk deployments.

### 5.2 Embedded Runtime Mode

```
┌──────────────────────────────────────┐
│          Agent Process               │
│                                      │
│  Agent ──► Kernel (full pipeline) ──► Real Executors ──► Tool
│         (cooperative routing)        │
└──────────────────────────────────────┘
```

- **Mediation**: Cooperative. Agent code must route all tool calls through the kernel.
- **Tamper resistance**: None. Shares address space.
- **Taint fidelity**: Full. Real executors auto-taint; content scanning operates on actual tool output.
- **Use case**: Applications that control the tool execution layer and can guarantee routing through the kernel.

### 5.3 Sidecar Mode

```
┌───────────────────┐       ┌──────────────────────┐
│   Agent Process   │ HTTP  │   Sidecar Process    │
│                   │◄─────►│                      │
│  SidecarClient ───┼───────┼──► Ari Kernel        │
│                   │ :8787 │  ──► Real Executors   │
│  SidecarGuard     │       │  ──► Audit Log        │
│  (optional)       │       │  ──► Principal Reg    │
└───────────────────┘       └──────────────────────┘
```

- **Mediation**: Mandatory within the process boundary. The agent communicates only via authenticated HTTP. No shared memory or direct function call path to tools.
- **Tamper resistance**: Process-isolated. Agent cannot inspect or modify kernel state, policy, token stores, or audit logs.
- **Identity**: Derived from API key (per-principal credentials). Client-supplied `principalId` is rejected if it mismatches the authenticated identity.
- **Admission control**: Per-principal rate limiting, concurrent execution limits, firewall instance caps.
- **Taint fidelity**: Full.
- **Use case**: Production deployments requiring strong containment. Highest assurance when combined with host sandboxing.

### 5.4 Sidecar Guard (Optional)

The `SidecarGuard` monkey-patches Node.js runtime APIs (`globalThis.fetch`, `child_process.*`) to redirect calls through the sidecar client. This is **cooperative interception**, not syscall hooking. It reduces accidental bypass but does not prevent deliberate circumvention via native addons, FFI, or alternative runtimes.

### 5.5 Deployment Mode Comparison

| Property | Middleware | Embedded | Sidecar |
|----------|-----------|----------|---------|
| Mediation | Cooperative | Cooperative | Mandatory (process boundary) |
| Tamper resistance | None | None | Process-isolated |
| Identity binding | None | None | API key → principalId |
| Rate limiting | None | None | Per-principal + global |
| Taint fidelity | Partial (stub executors) | Full | Full |
| Bypass resistance | Low | Moderate | High (within process boundary) |

---

## 6. In-Scope Attacks

The following attack patterns are within Ari Kernel's defensive scope:

| Attack | Mitigation |
|--------|-----------|
| Prompt injection → sensitive file read | Path constraints + behavioral rule `web_taint_sensitive_probe` → quarantine |
| Prompt injection → HTTP exfiltration | Behavioral rule `sensitive_read_then_egress` → quarantine; host constraints on egress |
| SSRF through mediated HTTP tools | `allowedHosts` constraint; HTTP executor blocks private IPs and validates redirects |
| Shell abuse through mediated executors | `allowedCommands` constraint; metacharacter rejection; direct spawn (`shell: false`) |
| Path traversal / symlink TOCTOU | O_NOFOLLOW at open + fstat validation + realpath check after open |
| Capability misuse within enforcement boundary | Token scoping (time, usage, principal binding); constraint intersection on delegation |
| SQL injection from untrusted input | Behavioral rule `tainted_database_write` blocks tainted DB mutations |
| Privilege escalation probing | Behavioral rule `denied_capability_then_escalation` → quarantine |
| Credential theft + exfiltration | Behavioral rule `secret_access_then_any_egress` → quarantine |
| Sidecar principal spoofing | API key → principalId binding; mismatched body `principalId` rejected |
| Resource exhaustion against sidecar | Per-principal rate limiting, concurrent execution limits, firewall instance caps |
| Regex DoS in policy rules | Input length cap (8192 bytes), fail-closed `UnsafeMatchError`, bounded output filter quantifiers |
| Capability token replay / double-spend | Atomic `consume()` with `callsUsed`/`maxCalls`, expiry enforcement, principal binding |

---

## 7. Out-of-Scope / Non-Goals

Ari Kernel does **not** attempt to defend against:

| Non-Goal | Rationale |
|----------|-----------|
| **OS-level syscall mediation** | Ari Kernel is a userspace library. It does not intercept `execve`, `open`, `connect`, or other syscalls. Deploy seccomp-BPF, AppArmor, or container isolation for OS-level enforcement. |
| **Arbitrary host compromise** | If the attacker has shell access to the host running the sidecar, all bets are off. Ari Kernel assumes the host is reasonably trustworthy. |
| **Ambient authority outside mediated tools** | Code that calls `fs.readFileSync()` or `child_process.execSync()` directly bypasses the kernel. Sidecar mode + SidecarGuard reduces but does not eliminate this risk. |
| **Supply-chain compromise of Ari Kernel's own dependencies** | If a compromised npm package runs in the kernel process, enforcement is void. Standard supply-chain hygiene applies. |
| **Covert channels not visible to the kernel** | Timing side-channels, steganography in allowed outputs, or communication via shared external state are not detectable. |
| **Cross-principal collusion (full prevention)** | The sidecar provides lightweight cross-principal provenance and alerting via three correlation rules: **CP-1** detects shared-store relay (A reads secret → writes shared resource → B reads same resource → B egresses); **CP-2** flags derived-sensitive taint on egress; **CP-3** detects egress-destination convergence (multiple principals egress to the same host within the correlation window when at least one had a sensitive read — catches out-of-band relay attacks without shared-store involvement). The `SharedTaintRegistry` marks shared resources as contaminated and the reading principal receives a `derived-sensitive` taint label. However, this is provenance tracking and alerting, not full information-flow control. Agents coordinating via channels fully invisible to the kernel (shared memory, timing side-channels, steganography in allowed outputs) are not detected. **Additional mitigations**: (1) Use the `anti-collusion` preset with explicit deny policies for cross-principal data flows. (2) Minimize capability overlap between principals sharing data channels. (3) Use container/VM isolation with network policy to restrict covert channels between agent processes. **Planned**: CP-4 unusual-host detection — per-principal baseline of normal egress destinations, alerting when a principal with sensitive reads contacts an unknown host. |
| **Full sandboxing** | Ari Kernel is not a sandbox. It enforces policy at the tool execution layer. Combine with container/VM isolation for defense-in-depth. |
| **Preventing prompt injection** | Ari Kernel contains the effects of injection, not the injection itself. |
| **Guaranteeing LLM reasoning correctness** | Out of scope entirely. The kernel is agnostic to model behavior. |

---

## 8. Assumptions

The following assumptions must hold for Ari Kernel's security properties to apply:

1. **All sensitive tool execution is routed through Ari Kernel.** In embedded/middleware mode, this depends on correct framework integration. In sidecar mode, this depends on the agent not having alternative paths to tools.

2. **The kernel code is trustworthy.** Ari Kernel's own source, dependencies, and runtime environment are not compromised.

3. **Policy authors are trusted administrators.** Policy configuration is not agent-controlled. Operators are responsible for writing correct, sufficiently restrictive policies.

4. **Cryptographic keys are protected.** Signing keys for capability tokens are stored securely and not accessible to agents.

5. **Sidecar mode is used for highest-assurance deployments.** Embedded and middleware modes provide weaker guarantees by design.

6. **The host environment is reasonably trustworthy** unless separately sandboxed. The sidecar process is not hardened against a compromised host.

7. **Tool executors correctly implement their security checks.** The kernel delegates tool-specific validation (SSRF checks, path resolution, metacharacter rejection) to executors. A bug in an executor weakens enforcement.

8. **The audit log is stored on media the attacker cannot silently replace.** The hash chain detects tampering but not wholesale replacement.

---

## 9. Residual Risks

The following risks remain after all current mitigations. They are documented honestly, not minimized.

| Risk | Severity | Details |
|------|----------|---------|
| **Middleware mode is cooperative and bypassable** | High | A malicious agent or compromised framework can call tools directly, bypassing enforcement entirely. Middleware mode is not suitable for high-assurance deployments. |
| **Sidecar is stronger but not equivalent to OS/kernel mediation** | Medium | The sidecar enforces a process boundary, but an agent with ambient OS permissions (network access, filesystem access) can bypass the sidecar entirely. Combine with container/VM isolation. |
| **Behavioral rules are heuristic and incomplete** | Medium | Six hardcoded rules cover common attack patterns. Novel patterns, slow-burn attacks that space steps across >20 events, or structurally benign-looking sequences may evade detection. |
| **Taint/content scanning can be evaded** | Medium | Label-based taint (not byte-level). Content scanning uses regex patterns that sophisticated encoding, obfuscation, or chunking can evade. |
| **Middleware taint boundary** | Medium | Middleware adapters enforce permit/deny decisions and call `observeToolOutput()` after tool execution to close the taint gap for content scanning and auto-taint derivation. However, taint fidelity is cooperative — the adapter must correctly feed output back. Custom adapters that do not call `observeToolOutput()` operate in degraded mode (pre-execution policy checks only). Multi-hop taint propagation is limited to input taint in middleware mode. |
| **Audit log is locally tamper-evident, not tamper-proof** | Low–Medium | Hash chain detects modification but not wholesale replacement. Not cryptographically signed. Forward to an external append-only store for production integrity. |
| **Benchmark coverage differs from real-world integrations** | Low | Benchmarks test kernel enforcement with controlled scenarios. Real-world agent frameworks, tool implementations, and attack techniques may differ. |
| **Operator misconfiguration** | Low–Medium | Overly permissive policies, missing constraints, or disabled authentication weaken all guarantees. Presets and fail-closed defaults mitigate but cannot prevent. |

---

## 10. Recommended Deployment Profiles

| Profile | Mode | Authentication | Rate Limiting | Taint | Isolation | Assurance |
|---------|------|---------------|---------------|-------|-----------|-----------|
| **Local development** | Middleware or embedded | None required | None | Partial (middleware) or full (embedded) | None | Low |
| **Embedded trusted-agent** | Embedded runtime | N/A (in-process) | N/A | Full | In-process | Moderate |
| **Sidecar production** | Sidecar | API key per principal | Per-principal + global | Full | Process boundary | High |
| **Sidecar + sandboxed host** | Sidecar | API key per principal | Per-principal + global | Full | Process + container/VM | Highest |

For production deployments handling sensitive data, **sidecar mode with per-principal API keys** is the minimum recommended configuration. For highest assurance, combine with a hardened container or VM that restricts the agent's ambient OS permissions.

---

## 11. Relationship to Existing Docs

| Document | Purpose |
|----------|---------|
| [Security Model](security-model.md) | Describes the system's security properties and enforcement mechanisms in detail: pipeline stages, capability tokens, taint propagation, behavioral detection, sidecar architecture. |
| [Reference Monitor](reference-monitor.md) | Formal specification of the enforcement architecture, mapping to Anderson (1972) reference monitor properties. Design rationale and pipeline invariants. |
| **Threat Model** (this document) | Defines attacker assumptions, protected assets, trust boundaries, in-scope and out-of-scope attacks, and residual risks. Scoped to the current implementation. |

These documents are complementary:
- The **security model** answers "how does enforcement work?"
- The **reference monitor spec** answers "what formal properties does the architecture satisfy?"
- The **threat model** answers "what are we defending against, and where do the defenses end?"
