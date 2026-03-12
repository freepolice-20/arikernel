# Known Limitations

Honest documentation of what Ari Kernel does not protect against, where enforcement boundaries have gaps, and what assumptions the system relies on.

> See also: [Threat Model](threat-model.md) | [Security Model](security-model.md) | [Reference Monitor](reference-monitor.md)

---

## Enforcement boundary

**Embedded mode is cooperative enforcement only.** The host process has ambient authority and can bypass the pipeline. If agent framework code, tool code, or injected dependencies invoke OS APIs directly (e.g., `fs.readFileSync`, raw `fetch`, `child_process.exec`), those calls are not mediated by the kernel. Embedded mode is suitable for development and trusted environments only.

**Sidecar mode is process-isolated but not OS-sandboxed.** The agent cannot access the policy engine, run-state, or audit log across the process boundary. However, the sidecar does not intercept syscalls. A compromised agent process can still make direct network calls or filesystem access unless the runtime environment restricts these at the OS level. Combine sidecar mode with container isolation, network policies, and restricted filesystem mounts for highest assurance. See [Execution Hardening](execution-hardening.md).

## Tool executors

**Database executor is a stub in v0.1.0.** The database executor validates and audits calls but does not execute real queries or connect to real databases. Cross-principal taint tracking for database tools works at the policy and taint-label level, but actual SQL injection prevention and query result inspection require a real adapter. Production database protection requires implementing a custom executor that connects to your database and wires through the kernel's taint and policy checks.

## Taint registry

**GlobalTaintRegistry has SQLite persistence but no TTL eviction.** Taint entries persist across restarts via the `ControlPlaneAuditStore`, but there is no automatic expiry mechanism. Under high principal churn (many short-lived agents registering taint), the registry will grow without bound. For high-volume deployments, implement periodic purging or monitor the `taint_events` table size.

## Network mediation

**DNS covert channels are not mediated.** The HTTP firewall intercepts HTTP/HTTPS requests but does not intercept DNS lookups. An attacker who controls the agent could exfiltrate small amounts of data via DNS TXT record queries or subdomain encoding. Mitigate with DNS filtering at the network layer (e.g., CoreDNS policies, cloud DNS firewalls).

**controlPlaneAuthToken is transmitted in HTTP headers.** The control plane and sidecar authenticate via bearer tokens in HTTP `Authorization` headers. This is secure over localhost (the default binding) but requires HTTPS for any non-localhost deployment. Without TLS, tokens are transmitted in plaintext.

**No mTLS between agent and sidecar.** The sidecar binds to `127.0.0.1` by default, which mitigates network-level interception. For non-localhost deployments (e.g., agent and sidecar in separate containers), mutual TLS should be configured at the infrastructure layer. Ari Kernel does not implement its own TLS termination.

## Content inspection

**Content scanner patterns are heuristic only.** The DLP output filter and `isSuspiciousGetExfil()` detector use pattern matching (regex, entropy analysis, base64/hex detection) to identify potential data exfiltration. These are defense-in-depth heuristics, not a security boundary. A determined attacker can encode data in ways that evade pattern detection. Do not rely on content scanning as a primary control.

## Replay and verification

**Replay verification is decision-replay only.** Deterministic replay re-evaluates security decisions from recorded traces but does not re-derive taint labels from original tool outputs. If the original trace was generated with stub executors, replay reflects stub behavior, not real-executor behavior. Replay verifies that the same policy would produce the same decisions given the same inputs — it does not verify that the inputs were correct.

## Benchmark coverage

**`path_ambiguity_bypass` scenario requires real FileExecutor wiring.** This benchmark scenario tests file path canonicalization (traversal via `../`, absolute paths, mixed separators). The simulation uses stub executors that grant all `file.read` requests without enforcing path constraints. The scenario documents the expected threat model but does not fully exercise `FileExecutor` path canonicalization end-to-end.
