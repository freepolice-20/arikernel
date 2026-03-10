# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in AriKernel, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. Email: Send details to the maintainers via the email listed in the repository's GitHub profile, or use [GitHub's private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability).
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

## Security Documentation

- [Threat Model](docs/threat-model.md) — attacker assumptions, trust boundaries, in-scope/out-of-scope attacks, residual risks
- [Security Model](docs/security-model.md) — enforcement mechanisms: capability tokens, taint propagation, behavioral detection
- [Reference Monitor](docs/reference-monitor.md) — formal enforcement architecture (Anderson, 1972)
- [Sidecar Mode](docs/sidecar-mode.md) — process-isolated deployment for production
- [Security Overview](docs/security-overview.md) — how the security documents relate to each other

For architecture details, see [ARCHITECTURE.md](ARCHITECTURE.md).
