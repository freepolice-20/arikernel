# Known Limitations

Honest documentation of what Ari Kernel does not protect against, where enforcement boundaries have gaps, and what assumptions the system relies on.

> See also: [Threat Model](threat-model.md) | [Security Model](security-model.md) | [Reference Monitor](reference-monitor.md)

---

## Python runtime scope

The Python runtime (`pip install arikernel`) uses **sidecar-authoritative** enforcement by default: all security decisions are delegated to the TypeScript sidecar over HTTP, providing process-boundary isolation. This means Python inherits all TypeScript enforcement capabilities (SSRF protection, behavioral rules, taint tracking, audit logging) via the sidecar.

Remaining Python-specific limitations:

- **Sidecar dependency** — the TypeScript sidecar must be running for Python enforcement to work. If the sidecar is unreachable, `create_kernel()` raises `ConnectionError`.
- **Local mode is dev-only** — `mode="local"` provides in-process enforcement for development and testing but does not offer process-boundary isolation and should not be used in production.
- **No persistent cross-run taint in local mode** — when using `mode="local"`, the Python runtime does not have an equivalent of the TypeScript `PersistentTaintRegistry`. In sidecar mode, the sidecar handles this.

---

## Enforcement boundary

**Embedded mode is cooperative enforcement only.** The host process has ambient authority and can bypass the pipeline. If agent framework code, tool code, or injected dependencies invoke OS APIs directly (e.g., `fs.readFileSync`, raw `fetch`, `child_process.exec`), those calls are not mediated by the kernel. Embedded mode is suitable for development and trusted environments only.

**Sidecar mode is process-isolated but not OS-sandboxed.** The agent cannot access the policy engine, run-state, or audit log across the process boundary. However, the sidecar does not intercept syscalls. A compromised agent process can still make direct network calls or filesystem access unless the runtime environment restricts these at the OS level. Combine sidecar mode with container isolation, network policies, and restricted filesystem mounts for highest assurance. See [Execution Hardening](execution-hardening.md).

## Tool executors

**Default database executor is a stub.** The default `DatabaseExecutor` validates and audits calls but does not execute real queries. A real `SqliteDatabaseExecutor` is available for SQLite databases — it supports structured `query` and `mutate` operations with parameterized queries, strict identifier validation, and no raw SQL passthrough. To use it:

```ts
import Database from "better-sqlite3";
import { SqliteDatabaseExecutor } from "@arikernel/tool-executors";
const executor = new SqliteDatabaseExecutor(new Database("app.db"));
registry.register(executor); // replaces the stub
```

For other databases (Postgres, MySQL), implement a custom `ToolExecutor` with the same structured-operations pattern. Do not accept raw SQL from agents.

## Taint registry

**GlobalTaintRegistry has SQLite persistence but no TTL eviction.** Taint entries persist across restarts via the `ControlPlaneAuditStore`, but there is no automatic expiry mechanism. Under high principal churn (many short-lived agents registering taint), the registry will grow without bound. For high-volume deployments, implement periodic purging or monitor the `taint_events` table size.

## Network mediation

**DNS covert channels are not mediated.** The HTTP firewall intercepts HTTP/HTTPS requests but does not intercept DNS lookups. An attacker who controls the agent could exfiltrate small amounts of data via DNS TXT record queries or subdomain encoding. Mitigate with DNS filtering at the network layer (e.g., CoreDNS policies, cloud DNS firewalls).

**controlPlaneAuthToken is transmitted in HTTP headers.** The control plane and sidecar authenticate via bearer tokens in HTTP `Authorization` headers. This is secure over localhost (the default binding) but requires HTTPS for any non-localhost deployment. Without TLS, tokens are transmitted in plaintext.

**No mTLS between agent and sidecar.** The sidecar binds to `127.0.0.1` by default, which mitigates network-level interception. For non-localhost deployments (e.g., agent and sidecar in separate containers), mutual TLS should be configured at the infrastructure layer. Ari Kernel does not implement its own TLS termination.

## Content inspection

**Content scanner patterns are heuristic and opt-in.** The DLP output filter is an optional hook (`onOutputFilter`) — it is not enabled by default. When registered, it and the `isSuspiciousGetExfil()` detector use pattern matching (regex, entropy analysis, base64/hex detection) to identify potential data exfiltration. These are defense-in-depth heuristics, not a security boundary. A determined attacker can encode data in ways that evade pattern detection. Do not rely on content scanning as a primary control.

## Capability token replay across replicas

**Grant consumption is local to a single `ITokenStore` instance.** The built-in `TokenStore` (in-memory) and `SqliteTokenStore` (single-file SQLite) both enforce atomic `consume()` with `callsUsed`/`maxCalls` tracking — but only within the same store instance. If multiple sidecar replicas hold independent stores and both receive a copy of the same signed grant (e.g., the agent forwards a grant token to a different replica, or both replicas issue from the same signing key), each store will independently accept and consume it. A `maxCalls: 1` grant can be used twice — once per replica.

**This is a known design boundary, not a bug.** The `ITokenStore` interface is the intended plug-in seam for shared consumption. To prevent double-spend in horizontally scaled deployments:

1. **Shared SQLite WAL file** — point all replicas at the same `SqliteTokenStore` database file (works for co-located processes).
2. **External shared store** — implement `ITokenStore` backed by Redis, Postgres, or another shared data store with atomic increment semantics.
3. **Single-writer architecture** — route all grant issuance and consumption through a single control plane instance.

Revocation has the same scope limitation: revoking a grant on one store does not propagate to independent stores.

**Test coverage:** `packages/runtime/__tests__/token-double-spend-multi-store.test.ts` explicitly demonstrates the replay risk across independent stores and confirms that a shared store eliminates it.

---

## Replay and verification

**Replay verification is decision-replay only.** Deterministic replay re-evaluates security decisions from recorded traces but does not re-derive taint labels from original tool outputs. If the original trace was generated with stub executors, replay reflects stub behavior, not real-executor behavior. Replay verifies that the same policy would produce the same decisions given the same inputs — it does not verify that the inputs were correct.

## Benchmark coverage

**`path_ambiguity_bypass` scenario requires real FileExecutor wiring.** This benchmark scenario tests file path canonicalization (traversal via `../`, absolute paths, mixed separators). The simulation uses stub executors that grant all `file.read` requests without enforcing path constraints. The scenario documents the expected threat model but does not fully exercise `FileExecutor` path canonicalization end-to-end.
