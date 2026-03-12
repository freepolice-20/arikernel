# Sidecar / Proxy Enforcement Mode

Ari Kernel can run as a standalone HTTP proxy — a **sidecar** — that intercepts every tool call from an AI agent and enforces your policy before execution.

> See also: [Architecture](../ARCHITECTURE.md) | [Security Model](security-model.md)

In this mode the agent does not link `@arikernel/runtime` directly. Instead it
sends a `POST /execute` request to the sidecar process; the sidecar enforces
the policy, runs the tool, and returns the result (or a denial).

## Why sidecar mode?

| Mode | Description |
|------|-------------|
| **Library** | `createKernel()` embedded in the agent process. Zero network overhead. TypeScript/JavaScript runtime (Python experimental, not in v0.1.0). |
| **Sidecar** | Separate process on port 8787. Language-agnostic — any HTTP client works. Isolation: policy bugs can't crash the agent. |
| **Decision server** (`apps/server`) | Session-based multi-principal API on port 9099. Returns decisions only; agent executes tools itself. Defaults to localhost binding, optional bearer auth (`AUTH_TOKEN`), 1 MB body limit, and per-IP rate limiting (120 req/min). |

## Security Notes

The sidecar is hardened for production deployment:

- **Localhost-only by default**: The server binds to `127.0.0.1`. External network exposure requires the explicit `--host 0.0.0.0` flag. Never expose the sidecar to untrusted networks without authentication.
- **Bearer token authentication**: Use `--auth-token <token>` to require a Bearer token on all requests (except `/health`). The token is compared using constant-time string comparison to prevent timing attacks.
- **Per-principal isolation**: Each agent gets its own kernel instance — quarantine, counters, and audit logs are independent.
- **Cross-principal correlation**: The `CrossPrincipalCorrelator` detects tag-team attacks across principals — shared-store relay (CP-1), derived-sensitive egress (CP-2), and egress-destination convergence (CP-3, catches out-of-band relay attacks where multiple agents converge on the same host).
- **Quarantine-on-alert**: When `quarantineOnAlert: true` is set in the correlator config, CP alerts automatically quarantine all offending principals — escalating from detection to enforcement. Both principals involved in a tag-team attack are immediately restricted.

```bash
# Production: localhost + auth
arikernel sidecar --policy ./policy.yaml --auth-token "$SIDECAR_TOKEN"

# Development: no auth, localhost only
arikernel sidecar --policy ./policy.yaml
```

When auth is enabled, all requests must include `Authorization: Bearer <token>`. The `/health` endpoint is exempt.

## Identity Binding Modes

The sidecar supports two identity binding modes that control how `principalId` is determined:

| Mode | How it works | Trust level |
|------|-------------|-------------|
| **Dev mode** (default) | Client supplies `principalId` in the request body. No cryptographic binding. | Low — the client can impersonate any principal. Suitable for local development only. |
| **Authenticated mode** | API keys are configured via `principals` config. Each Bearer token maps to a specific `principalId`. The sidecar derives identity from the API key lookup, not from the request body. If the body `principalId` conflicts with the authenticated identity, the request is rejected (403). | High — identity is server-bound, not client-supplied. Required for production multi-agent deployments. |

```typescript
// Authenticated mode: API key → principal binding
const server = createSidecarServer({
  policy: './policy.yaml',
  principals: {
    'sk-agent-a-token': { principalId: 'agent-a' },
    'sk-agent-b-token': { principalId: 'agent-b' },
  },
});
```

---

## Quick start

**1. Start the sidecar**

```bash
arikernel sidecar --policy ./arikernel.policy.yaml --port 8787
```

Output:
```
Ari Kernel sidecar listening on 127.0.0.1:8787
  Policy : ./arikernel.policy.yaml
  Audit  : ./sidecar-audit.db
  POST   : http://localhost:8787/execute
  Health : http://localhost:8787/health
```

**2. Call a tool from your agent**

```http
POST /execute
Content-Type: application/json
Authorization: Bearer <token>

{
  "principalId": "my-agent",
  "toolClass": "http",
  "action": "get",
  "params": { "url": "https://api.example.com/data" }
}
```

Response (allowed):
```json
{
  "allowed": true,
  "result": "...",
  "resultTaint": ["web:api.example.com"],
  "callId": "01JABCDE..."
}
```

Response (denied):
```json
{
  "allowed": false,
  "error": "Policy denied: shell execution is prohibited",
  "callId": "01JABCDE..."
}
```

## Enforcement modes

AriKernel supports two enforcement modes that control where tool execution happens:

### Embedded mode (default)

Tools execute in-process. The host process has direct access to executors.
Security is **cooperative** — the host could bypass the pipeline by calling
executors directly. Suitable for trusted environments or development.

### Sidecar mode (recommended for production)

Tools execute **only via the sidecar HTTP API**. The host process's
`ExecutorRegistry` is populated with `SidecarProxyExecutor` instances that
delegate all execution to the sidecar. The host **cannot register local
executors** or execute tools directly.

```
┌────────────────────────────┐       HTTP        ┌──────────────────────────┐
│   Agent + Runtime          │  ──────────────►  │   Sidecar process        │
│   (SidecarProxyExecutors)  │  POST /execute    │   (trusted)              │
│                            │  ◄──────────────  │                          │
│   No real executors        │    JSON result    │   Owns: real executors,  │
│   No direct tool access    │                   │   policy engine,         │
│   registerExecutor() →     │                   │   run-state, taint graph,│
│     throws Error           │                   │   audit DB, quarantine   │
└────────────────────────────┘                   └──────────────────────────┘
```

The sidecar is the **authoritative enforcement boundary**. The agent can
only submit tool calls and read its enforcement state. It cannot modify
policy, reset quarantine, bypass capability checks, or execute tools directly.

### Setting the enforcement mode

```typescript
import { createKernel } from '@arikernel/runtime';

const kernel = createKernel({
  preset: 'safe',
  mode: 'sidecar',
  sidecar: {
    baseUrl: 'http://localhost:8787',
    authToken: process.env.SIDECAR_TOKEN,
  },
});

const firewall = kernel.createFirewall();
// firewall.registerExecutor() → throws Error in sidecar mode
// firewall.execute() → proxied to sidecar HTTP API
```

Or directly with `createFirewall`:

```typescript
import { createFirewall } from '@arikernel/runtime';

const firewall = createFirewall({
  principal: { name: 'my-agent', capabilities: [...] },
  policies: [...],
  mode: 'sidecar',
  sidecar: {
    baseUrl: 'http://localhost:8787',
    authToken: process.env.SIDECAR_TOKEN,
  },
});
```

## Embedded vs sidecar: when to use which

| Criterion | Embedded (`mode: "embedded"`) | Sidecar (`mode: "sidecar"`) |
|-----------|-------------------------------|----------------------------|
| Latency | ~0ms (in-process) | ~1ms (localhost HTTP) |
| Language | TypeScript/JavaScript (Python experimental) | Any language with HTTP |
| Isolation | Agent can inspect internals | Policy state is opaque |
| Executor access | Direct — host can bypass pipeline | None — host has proxy executors only |
| Quarantine bypass | Agent could tamper with in-process state | Agent has no way to reset quarantine |
| registerExecutor() | Works normally | Throws Error |
| Deployment | Single process | Two processes (or containers) |
| Best for | Trusted first-party agents, dev | Untrusted/third-party agents, production |

## API reference

### `POST /execute`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `principalId` | string | yes* | Agent identifier. Each principal gets its own run-state and audit log. *In authenticated mode (API key binding), this is derived from the API key and the body value must match or be omitted.* |
| `toolClass` | string | yes | One of: `http`, `file`, `shell`, `database`, `retrieval` |
| `action` | string | yes | Tool-specific action (`get`, `post`, `read`, `write`, `exec`, `query`, ...). Case-insensitive — normalized to lowercase internally. |
| `params` | object | yes | Tool-specific parameters (passed to the executor) |
| `taint` | TaintLabel[] | no | Upstream taint labels to attach to this call (objects with `source`, `origin`, `confidence`, `addedAt`) |
| `capabilityToken` | string | no | Serialized capability token from a prior `/request-capability` call. If provided with a signing key, the token is cryptographically verified. If omitted, the sidecar auto-issues a server-side grant. |

**Capability token flow**: Clients can either (a) call `/request-capability` first to obtain a `grantId`, then pass a serialized `capabilityToken` in `/execute`, or (b) omit the token and let the sidecar auto-issue a grant server-side. Option (a) provides explicit capability tracking; option (b) is simpler for trusted deployments.

HTTP status codes:
- `200` — call allowed and executed successfully
- `400` — malformed request
- `401` — missing or malformed Authorization header (when auth is enabled)
- `403` — call denied by policy, quarantine, or invalid auth token
- `429` — rate limit exceeded (includes `Retry-After` header)
- `500` — internal error during execution

### `POST /request-capability`

Request a capability grant from the sidecar. Returns a `grantId` that can be
used in subsequent `/execute` calls for protected actions.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `principalId` | string | yes | Agent identifier |
| `capabilityClass` | string | yes | Capability class (e.g. `http.write`, `file.read`, `shell.exec`) |
| `constraints` | object | no | Optional constraints to narrow the grant (e.g. `{ allowedHosts: ["api.example.com"] }`) |
| `justification` | string | no | Why the capability is needed |

Response (granted):
```json
{
  "granted": true,
  "grantId": "grant_01JABCDE...",
  "reason": "Capability granted for http.write"
}
```

Response (denied):
```json
{
  "granted": false,
  "reason": "Principal lacks http.write capability"
}
```

HTTP status codes:
- `200` — capability granted
- `400` — malformed request
- `403` — capability denied by policy

### `POST /status`

Returns the principal's enforcement state (quarantine, counters).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `principalId` | string | yes | Agent identifier (must already exist from a prior `/execute` call) |

Response:
```json
{
  "principalId": "my-agent",
  "restricted": false,
  "runId": "01JABCDE...",
  "counters": {
    "deniedActions": 3,
    "capabilityRequests": 7,
    "sensitiveFileReadAttempts": 1,
    "externalEgressAttempts": 0
  },
  "quarantine": null
}
```

When the principal is quarantined:
```json
{
  "restricted": true,
  "quarantine": {
    "reason": "Exceeded denied action threshold (3)",
    "triggerType": "denied_action_limit",
    "timestamp": "2026-03-09T..."
  }
}
```

HTTP status codes:
- `200` — status returned
- `400` — missing or invalid `principalId`
- `404` — unknown principal (no prior `/execute` call)

### `GET /health`

Returns `{ "status": "ok", "service": "arikernel-sidecar" }`.

## TypeScript client

```typescript
import { SidecarClient } from '@arikernel/sidecar';

const client = new SidecarClient({
  baseUrl: 'http://localhost:8787',
  principalId: 'my-agent',
  authToken: process.env.SIDECAR_TOKEN,  // Optional: required if server uses --auth-token
});

const result = await client.execute('http', 'GET', { url: 'https://api.example.com/data' });
if (!result.allowed) {
  console.error('Denied:', result.error);
}

// Request a capability grant for protected actions
const cap = await client.requestCapability('http.write', {
  constraints: { allowedHosts: ['api.example.com'] },
});
if (cap.granted) {
  console.log('Grant ID:', cap.grantId);
}

// Check enforcement state (quarantine, counters)
const status = await client.status();
console.log('Restricted:', status.restricted);
console.log('Denied actions:', status.counters.deniedActions);
```

## Embedding the server

```typescript
import { createSidecarServer } from '@arikernel/sidecar';

const server = createSidecarServer({
  port: 8787,
  // host: '0.0.0.0',            // Default: '127.0.0.1' (localhost only)
  // authToken: 'my-secret',     // Optional: require Bearer token auth
  policy: './arikernel.policy.yaml',
  auditLog: './sidecar-audit.db',
});

await server.listen();
// ...
await server.close();
```

## Per-principal isolation

Each unique `principalId` gets its own:
- Kernel instance with independent run-state
- Behavioral rule counters (quarantine is per-principal, not global)
- SQLite audit database at `<auditDir>/<principalId>.db`

This means if `agent-A` triggers quarantine, `agent-B` is unaffected.

## Audit replay

Because the sidecar writes standard Ari Kernel audit logs, the existing
`arikernel replay` command works without modification:

```bash
arikernel replay --db ./my-agent.db --latest --verbose
```

## Passing taint labels

When a call result carries taint (e.g. web content fetched via HTTP), pass
those labels on subsequent calls to propagate provenance:

```http
POST /execute
{
  "principalId": "agent-1",
  "toolClass": "file",
  "action": "write",
  "params": { "path": "/tmp/out.txt", "content": "..." },
  "taint": ["web:api.example.com"]
}
```

If your policy denies tainted writes (`taintLabels: ['web:*']`), this call
will be blocked with `allowed: false`.

## Security examples

Run the security demo to see prompt injection defense, quarantine escalation,
and status introspection in action:

```bash
pnpm demo:sidecar:security
```

See [examples/sidecar-security-demo/agent.ts](../examples/sidecar-security-demo/agent.ts) for the full source.

---

## High-Assurance Deployment

Sidecar mode is designed to work alongside hardened runtime environments. The sidecar mediates agent tool execution — it evaluates capability tokens, taint, policy rules, and behavioral patterns before any tool executes. It does **not** mediate host syscalls, network connections, or filesystem access at the OS level.

For production deployments handling sensitive data, pair the sidecar with:

| Control | Purpose |
|---------|---------|
| **Containerized runners** (Docker, gVisor, Firecracker) | Restrict ambient OS capabilities — the agent process cannot access tools outside the sidecar |
| **Network policy restrictions** (iptables, eBPF, Kubernetes NetworkPolicy) | Prevent egress paths that bypass the sidecar's HTTP executor |
| **Restricted process permissions** (`--cap-drop ALL`, read-only root filesystem) | Limit what the agent can do even if it bypasses the sidecar |
| **Separate UID for agent processes** | Prevent privilege escalation to the sidecar process |

```
  ┌─────────────────────────────────────────────────┐
  │  Container / VM                                  │
  │                                                  │
  │  ┌──────────────┐        ┌──────────────────┐   │
  │  │ Agent Process │  HTTP  │ Sidecar Process  │   │
  │  │ (restricted)  │──────►│ (Ari Kernel)     │   │
  │  │               │ :8787  │                  │   │
  │  │ No direct     │        │ Policy engine    │   │
  │  │ tool access   │        │ Taint tracker    │   │
  │  │               │        │ Behavioral rules │   │
  │  └──────────────┘        │ Audit log        │   │
  │                           └──────────────────┘   │
  │                                                  │
  │  Network policy: egress restricted               │
  │  Filesystem: read-only except /tmp               │
  │  Capabilities: dropped                           │
  └─────────────────────────────────────────────────┘
```

Together, the sidecar (application-layer enforcement) and the hardened container (system-layer isolation) provide defense-in-depth. The sidecar evaluates every tool call against security policy; the container ensures the agent cannot circumvent that evaluation.
