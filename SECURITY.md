# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in AriKernel, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. **Email**: Send details to [security@arikernel.dev](mailto:security@arikernel.dev), or use [GitHub's private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability).
2. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours of receipt
- **Initial assessment**: Within 7 days
- **Fix or mitigation**: Within 30 days for critical issues, 90 days for others
- **Disclosure**: Coordinated disclosure after a fix is available

### Scope

The following are in scope for security reports:

- Policy bypass (capability grants that violate configured constraints)
- Constraint composition flaws (grants that broaden rather than narrow)
- Taint tracking evasion (untrusted data losing provenance labels)
- Sidecar authentication bypass
- Quarantine escape (agent circumventing restricted mode)
- Audit log integrity (tampering or omission of security events)

The following are out of scope:

- Vulnerabilities in upstream dependencies (report to the dependency maintainer)
- Denial-of-service against the sidecar (covered by rate limiting guidance in docs)
- Issues requiring physical access to the host

### Recognition

We credit reporters in release notes (with permission). If you prefer to remain anonymous, let us know in your report.

## Security Design

AriKernel's design draws on the reference monitor concept (Anderson, 1972), adapted to userspace agent runtimes. Key security properties:

- **Mediation**: All tool calls routed through the kernel are subject to enforcement. In embedded mode this is cooperative (the framework must route calls through the kernel). In sidecar mode, the process boundary provides mandatory mediation — no direct agent-to-tool path exists.
- **Tamper-resistant state**: Quarantine and run-state counters are managed by the kernel. In sidecar mode, the agent has no access to kernel state. In embedded mode, kernel state lives in the same process and is not protected by a hardware boundary.
- **Least privilege**: Capability grants use intersection semantics (can only narrow, never broaden)
- **Tamper-evident audit**: Every decision is logged in a SHA-256 hash-chained store. The chain detects modification after the fact but does not prevent it — see [Security Model § Hash Chain Limitations](docs/security-model.md#24-audit-and-tamper-evidence).

## Limitations and Non-Goals

AriKernel is a **userspace enforcement layer**, not a hardware-backed sandbox. The following limitations are inherent to this architecture and should be understood before deployment:

### What AriKernel Does NOT Protect Against

- **Ambient authority bypass**: Any agent with access to raw `fs`, `net`, `child_process`, or equivalent APIs can bypass AriKernel entirely. Sidecar mode mitigates this by placing the kernel in a separate process, but the agent process must still be restricted from making direct system calls (via container sandboxing, seccomp, or equivalent OS-level policy).
- **Compromised host or runtime**: If the Node.js process itself is compromised, kernel state and enforcement can be tampered with. AriKernel assumes a trusted runtime environment. (Note: the Python runtime is experimental and not part of the v0.1.0 release.)
- **Supply chain attacks**: Malicious dependencies loaded into the agent process operate with full ambient authority. AriKernel does not inspect or restrict package-level code execution.
- **Covert channels**: Exfiltration via DNS, timing side channels, error-based channels, or other non-tool-call communication paths is not mediated.
- **Multi-agent collusion (full prevention)**: The cross-principal correlator and shared-store taint tracking provide lightweight provenance and alerting, not full information-flow control. Agents that coordinate without shared stores (e.g., pure network choreography) are not detected.

### NIST Reference Monitor Properties

NIST's reference monitor definition (Anderson, 1972) requires three properties: **complete mediation** (always invoked), **tamperproofing**, and **verifiability**. AriKernel's compliance differs by deployment mode:

| Property | Sidecar Mode | Embedded/Middleware Mode |
|---|---|---|
| Complete mediation | Yes, if ambient authority is removed via sandboxing | No — cooperative only; framework must route calls through the kernel |
| Tamperproof | Yes — kernel state is in a separate process | No — kernel state is in-process and accessible to the agent |
| Verifiable | Partially — audit chain is tamper-evident, not tamperproof | Same |

**For production deployments requiring mandatory mediation, use sidecar mode with an external sandbox** (container with restricted capabilities, seccomp profile, read-only filesystem, outbound network policy). Without this, AriKernel provides defense-in-depth against accidental misuse but not against a determined adversary with code execution.

### Egress Model Limitations

The egress detection model treats HTTP write methods (POST/PUT/PATCH/DELETE) as egress and HTTP GET as ingress. Additional heuristics detect exfiltration via:
- Long query strings and parameter values
- High-entropy URL path segments (base64/hex encoded data)
- GET-with-params after sensitive file reads

However, subtle exfiltration channels remain possible: low-entropy chunked exfil, HTTP header encoding, DNS-based exfil, and timing channels. For high-security deployments, combine AriKernel's behavioral detection with network-level egress controls (allowlisted domains, outbound proxy).

## Security Documentation

- [Threat Model](docs/threat-model.md) — attacker assumptions, trust boundaries, in-scope/out-of-scope attacks, residual risks
- [Security Model](docs/security-model.md) — enforcement mechanisms: capability tokens, taint propagation, behavioral detection
- [Reference Monitor](docs/reference-monitor.md) — formal enforcement architecture (Anderson, 1972)
- [Sidecar Mode](docs/sidecar-mode.md) — process-isolated deployment for production
- [Security Overview](docs/security-overview.md) — how the security documents relate to each other

For architecture details, see [ARCHITECTURE.md](ARCHITECTURE.md).
