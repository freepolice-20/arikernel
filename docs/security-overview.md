# Security Documentation Map

How Ari Kernel's security documents relate to each other.

---

## Documents

| Document | Question it answers | Audience |
|----------|-------------------|----------|
| [Threat Model](threat-model.md) | What are we defending against? Where do the defenses end? | Security engineers, red-teamers, auditors |
| [Security Model](security-model.md) | How does enforcement work? What mechanisms are in place? | Security researchers, system architects |
| [Reference Monitor](reference-monitor.md) | What formal properties does the architecture satisfy? | Formal methods researchers, auditors |
| [Sidecar Mode](sidecar-mode.md) | How does process-isolated deployment work? What are the enforcement modes? | DevOps, security engineers, operators |
| [Architecture](../ARCHITECTURE.md) | How is the system implemented? What are the packages and pipeline stages? | Developers, contributors |

## Reading order

**For a security review**: Threat Model -> Security Model -> Reference Monitor -> Sidecar Mode

**For deployment hardening**: Sidecar Mode -> Threat Model (deployment profiles) -> [Execution Hardening](execution-hardening.md)

**For understanding enforcement**: Security Model (pipeline) -> Reference Monitor (formal properties) -> Architecture (implementation)

## How they fit together

```
                    Threat Model
                   (what we defend against)
                          │
              ┌───────────┴───────────┐
              ▼                       ▼
       Security Model          Reference Monitor
    (enforcement mechanisms)   (formal properties)
              │                       │
              └───────────┬───────────┘
                          ▼
                    Sidecar Mode
              (deployment isolation)
                          │
                          ▼
                    Architecture
                  (implementation)
```

- The **threat model** defines attacker assumptions, protected assets, trust boundaries, and residual risks. It is scoped to the current implementation, not idealized architecture.
- The **security model** describes enforcement mechanisms in detail: the 10-stage pipeline, capability tokens, taint propagation, behavioral detection, and quarantine.
- The **reference monitor** spec maps the architecture to Anderson (1972) reference monitor properties. It specifies which properties hold in each deployment mode.
- **Sidecar mode** documents the process-isolated deployment that provides the strongest enforcement boundary, including the `embedded` vs `sidecar` enforcement modes.
- The **architecture** doc describes the implementation: package structure, pipeline stages, and deployment modes.

## Key security invariants

These invariants are documented across the security docs and verified by the implementation:

1. **Fail-closed**: Unknown tool classes, actions, and capability classes are denied. Invalid regex patterns in policy rules trigger `UnsafeMatchError` and deny the match (not crash).
2. **Monotonic narrowing**: Capability delegation can only narrow, never broaden. Constraint intersection enforces this at issuance.
3. **Taint stickiness**: Once a run is tainted, taint labels cannot be removed. The `tainted` flag is permanent.
4. **Quarantine irreversibility**: Once entered, restricted mode cannot be exited within the run.
5. **Atomic token consumption**: `TokenStore.consume()` validates and increments in a single operation (no TOCTOU).
6. **TOCTOU-safe file access**: O_NOFOLLOW at open + fstat validation + realpath check after open.
7. **Principal identity binding** (sidecar): API key -> principalId mapping. Client-supplied principalId must match authenticated identity.

## What is NOT claimed

The security docs explicitly document these non-goals:

- Ari Kernel is not a sandbox (no syscall interception)
- Embedded mode enforcement is cooperative, not mandatory
- The sidecar guard is cooperative monkey-patching, not OS-level hooking
- The audit hash chain is tamper-evident, not tamper-proof
- Taint tracking is label-based, not byte-level
- Behavioral rules are heuristic with a bounded window (20 events)
