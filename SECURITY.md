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

AriKernel follows a reference monitor architecture. Key security properties:

- **Complete mediation**: All tool calls route through the enforcement pipeline
- **Tamperproof state**: Quarantine and run-state counters are server-side (agents cannot reset them)
- **Least privilege**: Capability grants use intersection semantics (can only narrow, never broaden)
- **Audit trail**: Every decision is logged with cryptographic integrity markers

For architecture details, see [ARCHITECTURE.md](ARCHITECTURE.md).
