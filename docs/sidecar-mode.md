# Sidecar / Proxy Enforcement Mode

Ari Kernel can run as a standalone HTTP proxy — a **sidecar** — that intercepts every tool call from an AI agent and enforces your policy before execution.

> See also: [Architecture](../ARCHITECTURE.md) | [Security Model](security-model.md)

In this mode the agent does not link `@arikernel/runtime` directly. Instead it
sends a `POST /execute` request to the sidecar process; the sidecar enforces
the policy, runs the tool, and returns the result (or a denial).

## Why sidecar mode?

| Mode | Description |
|------|-------------|
| **Library** | `createKernel()` embedded in the agent process. Zero network overhead, but requires TypeScript/JavaScript. |
| **Sidecar** | Separate process on port 8787. Language-agnostic — any HTTP client works. Isolation: policy bugs can't crash the agent. |
| **Decision server** (`apps/server`) | Session-based multi-principal API. Returns decisions only; agent executes tools itself. |

## Quick start

**1. Start the sidecar**

```bash
arikernel sidecar --policy ./arikernel.policy.yaml --port 8787
```

Output:
```
Ari Kernel sidecar listening on port 8787
  Policy : ./arikernel.policy.yaml
  Audit  : ./sidecar-audit.db
  POST   : http://localhost:8787/execute
  Health : http://localhost:8787/health
```

**2. Call a tool from your agent**

```http
POST /execute
Content-Type: application/json

{
  "principalId": "my-agent",
  "toolClass": "http",
  "action": "GET",
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

## Trust boundary

The sidecar enforces a **process-level trust boundary**:

```
┌────────────────────┐       HTTP        ┌──────────────────────────┐
│   Agent process    │  ──────────────►  │   Sidecar process        │
│   (untrusted)      │  POST /execute    │   (trusted)              │
│                    │  ◄──────────────  │                          │
│   Has no access    │    JSON result    │   Owns: policy engine,   │
│   to policy engine │                   │   run-state, taint graph,│
│   or run-state     │                   │   audit DB, quarantine   │
└────────────────────┘                   └──────────────────────────┘
```

The agent can only submit tool calls and read its enforcement state.
It cannot modify policy, reset quarantine, or bypass capability checks.

## Embedded vs sidecar: when to use which

| Criterion | Embedded (`createKernel`) | Sidecar |
|-----------|--------------------------|---------|
| Latency | ~0ms (in-process) | ~1ms (localhost HTTP) |
| Language | TypeScript/JavaScript only | Any language with HTTP |
| Isolation | Agent can inspect internals | Policy state is opaque |
| Quarantine bypass | Agent could theoretically tamper with in-process state | Agent has no way to reset quarantine |
| Deployment | Single process | Two processes (or containers) |
| Best for | Trusted first-party agents | Untrusted/third-party agents, polyglot environments |

## API reference

### `POST /execute`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `principalId` | string | yes | Agent identifier. Each principal gets its own run-state and audit log. |
| `toolClass` | string | yes | One of: `http`, `file`, `shell`, `database`, `retrieval` |
| `action` | string | yes | Tool-specific action (`GET`, `POST`, `read`, `write`, `exec`, `query`, …) |
| `params` | object | yes | Tool-specific parameters (passed to the executor) |
| `taint` | string[] | no | Upstream taint labels to attach to this call |

HTTP status codes:
- `200` — call allowed and executed successfully
- `400` — malformed request
- `403` — call denied by policy or quarantine
- `500` — internal error during execution

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
});

const result = await client.execute('http', 'GET', { url: 'https://api.example.com/data' });
if (!result.allowed) {
  console.error('Denied:', result.error);
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
