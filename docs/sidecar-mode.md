# Sidecar / Proxy Enforcement Mode

Ari Kernel can run as a standalone HTTP proxy — a **sidecar** — that intercepts
every tool call from an AI agent and enforces your policy before execution.

In this mode the agent does not link `@arikernel/runtime` directly. Instead it
sends a `POST /execute` request to the sidecar process; the sidecar enforces
the policy, runs the tool, and returns the result (or a denial).

## Why sidecar mode?

| Mode | Description |
|------|-------------|
| **Library** | `createFirewall()` embedded in the agent process. Zero network overhead, but requires TypeScript/JavaScript. |
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
- Firewall instance with independent run-state
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
