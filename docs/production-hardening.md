# Production Hardening Checklist

A concise deployment checklist for running Ari Kernel in production environments.

> See also: [Sidecar Mode](sidecar-mode.md) | [Execution Hardening](execution-hardening.md) | [Threat Model](threat-model.md) | [Known Limitations](known-limitations.md)

---

## Required

### Use sidecar mode

```typescript
const server = new SidecarServer({
  mode: "sidecar",
  preset: "safe",
  authToken: process.env.AUTH_TOKEN,
});
```

Embedded mode runs tools in the same process as the agent. The agent (or injected code) can bypass the kernel by calling OS APIs directly. **Embedded mode must not be used in production.** Sidecar mode enforces policy across a process boundary — the agent has no in-process path to tools that bypasses the kernel.

### Configure per-principal API keys

```typescript
const server = new SidecarServer({
  principals: [
    { name: "agent-a", apiKey: "ak-agent-a-..." },
    { name: "agent-b", apiKey: "ak-agent-b-..." },
  ],
});
```

Using `authToken` alone authenticates the request but does not bind identity. Per-principal API keys ensure each agent gets an isolated firewall instance with independent quarantine state. Without identity binding, one compromised agent's quarantine does not isolate it from other principals.

### Set control plane authToken

If deploying the centralized control plane (`@arikernel/control-plane`), the `authToken` configuration is required. In `NODE_ENV=production`, the control plane throws at startup if `authToken` is not set. In non-production, it emits a warning.

```typescript
const cp = new ControlPlaneServer({
  signingKey: generateSigningKey(),
  policy: rules,
  authToken: process.env.CP_AUTH_TOKEN,  // required in production
});
```

### Set FILE_EXECUTOR_ROOT

```bash
export FILE_EXECUTOR_ROOT=/app/workspace
```

Without this, the `FileExecutor` defaults to `process.cwd()`, which allows reads anywhere under the working directory. Set it to an explicit path that restricts file access to the intended workspace.

### Set signingKey for capability tokens

In multi-agent deployments, set `signingKey` on the control plane to enable Ed25519 signed decision receipts. This allows sidecars and clients to cryptographically verify that a decision was issued by a trusted control plane instance.

```typescript
import { generateSigningKey } from "@arikernel/control-plane";
const key = generateSigningKey(); // store securely, reuse across restarts
```

---

## Recommended

### Set NODE_ENV=production

```bash
export NODE_ENV=production
```

This activates startup guards that throw on misconfiguration:
- Sidecar server throws if `principals` is not configured
- Control plane throws if `authToken` is not set
- Console warnings are replaced with hard errors

### Use a persistent audit log path

```typescript
const server = new SidecarServer({
  auditLog: "/var/lib/arikernel/audit.db",  // not :memory:
});
```

The default `:memory:` audit log is lost on process restart. Point it at a persistent path for forensic replay, compliance reporting, and incident investigation.

### Enable quarantineOnAlert

```typescript
const server = new SidecarServer({
  correlatorConfig: {
    quarantineOnAlert: true,
  },
});
```

When the cross-principal correlator fires an alert (CP-1: shared resource contamination, CP-2: taint relay, CP-3: egress convergence), this setting auto-quarantines all offending principals. Without it, alerts are emitted but principals continue executing.

### Tune retentionWindowMs

```typescript
const server = new SidecarServer({
  persistentTaint: {
    enabled: true,
    retentionWindowMs: 3600_000,  // 1 hour — tune for your run frequency
  },
});
```

The persistent taint registry carries security-relevant state across runs. The retention window controls how long taint events are considered active. Too short and cross-run attacks succeed; too long and stale state accumulates.

---

## Compliance reporter

The `arikernel compliance-report` CLI command generates a structured evidence report covering deployment mode, policy state, security protections, benchmark coverage, and attack simulation availability.

```bash
arikernel compliance-report --markdown > evidence.md
```

**What it verifies**: deployment configuration, policy file presence and version, available security features (taint tracking, behavioral rules, audit logging, replay), benchmark test coverage.

**What it does not verify**: runtime correctness of enforcement decisions, OS-level isolation, network policy enforcement, secret management practices, or whether the sidecar is actually deployed (it inspects configuration, not runtime state).
