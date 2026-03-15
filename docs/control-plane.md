# Ari Kernel Control Plane

Centralized policy decision service for multi-agent deployments. Moves enforcement logic out of individual agent processes into a shared, auditable service.

## Architecture

```
Agent 1 ──> Sidecar 1 ──┐
                         ├──> Control Plane (port 9090)
Agent 2 ──> Sidecar 2 ──┘        │
                                  ├── Policy Engine (YAML rules)
                                  ├── Global Taint Registry
                                  ├── Request Nonce Store (replay protection)
                                  ├── SQLite Audit Log
                                  └── Ed25519 Decision Signing
```

Each sidecar sends a `POST /decision` request before executing a tool call. The control plane evaluates the request against loaded policies, enriches taint labels from the global registry, signs the verdict with Ed25519, and returns a signed decision receipt. The sidecar enforces the decision locally.

## Decision Flow

1. Agent issues tool call to sidecar
2. Sidecar serializes the call into a `DecisionRequest` (with optional `requestNonce`)
3. Sidecar sends `POST /decision` to control plane
4. Control plane checks `requestNonce` for replay (rejects duplicates with 409)
5. Control plane enriches taint labels from the global registry
6. Control plane evaluates policies via `PolicyEngine`
7. Control plane generates `decisionId`, signs the receipt with Ed25519
8. Sidecar receives `DecisionResponse` with full signed receipt
9. If `allow`: sidecar executes the tool call locally
10. If `deny` or `require-approval`: sidecar rejects without executing

## API

### `POST /decision`

**Request:**
```json
{
  "principalId": "agent-1",
  "toolClass": "http",
  "action": "POST",
  "parameters": { "url": "https://api.example.com/data" },
  "taintLabels": [],
  "runId": "run-abc123",
  "timestamp": "2026-03-10T12:00:00.000Z",
  "requestNonce": "client-unique-nonce-001"
}
```

The `requestNonce` field is optional. When provided, the control plane rejects duplicate nonces within the TTL window (5 minutes), returning HTTP 409.

**Response (signed receipt):**
```json
{
  "decision": "deny",
  "decisionId": "dec-1741612800000-a1b2c3d4",
  "reason": "Tainted request blocked",
  "policyVersion": "1.0.0",
  "policyHash": "3f2a7b9c1e4d5a08",
  "kernelBuild": "arikernel-cp-0.1.0",
  "timestamp": "2026-03-10T12:00:00.001Z",
  "nonce": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
  "signature": "ed25519-hex-signature-128-chars...",
  "matchedRule": { "id": "deny-tainted-http", "..." : "..." },
  "taintLabels": [{ "source": "web", "origin": "injected", "..." : "..." }]
}
```

Every response includes:

| Field | Description |
|-------|-------------|
| `decisionId` | Unique identifier for this specific decision |
| `policyVersion` | Version label of the loaded policy |
| `policyHash` | SHA-256 prefix (16 hex chars) of the loaded policy ruleset |
| `kernelBuild` | Kernel build identifier |
| `nonce` | 16-byte cryptographic nonce (server-generated) |
| `signature` | Ed25519 signature over the canonical receipt payload |

### `POST /taint/register`

Register taint labels in the global cross-agent registry.

```json
{
  "principalId": "agent-a",
  "runId": "run-1",
  "labels": [{ "source": "web", "origin": "https://evil.com", "confidence": 0.95, "addedAt": "..." }],
  "resourceIds": ["/shared/data.json"]
}
```

### `POST /taint/query`

Query taint labels on a resource.

```json
{ "resourceId": "/shared/data.json" }
```

### `GET /health`

Unauthenticated liveness probe. Returns `{ "status": "ok" }`.

## Replay Protection

The control plane provides two layers of replay protection:

### Request-level (client nonces)

Clients can include a `requestNonce` in the decision request. The control plane stores recent nonces in a time-windowed store (5-minute TTL). If a duplicate nonce is received, the request is rejected with HTTP 409:

```json
{ "error": "Duplicate requestNonce — request already processed" }
```

### Response-level (server nonces)

Every signed response includes a unique 16-byte nonce. Clients verifying responses use a `NonceStore` to track seen nonces and reject replayed decisions:

```typescript
import { DecisionVerifier, NonceStore } from "@arikernel/control-plane";

const verifier = new DecisionVerifier(publicKeyHex);
const nonces = new NonceStore();

const valid = verifier.verify(response, nonces);
// Second verification of the same response returns false
```

## Decision Signing & Receipt Verification

Every decision is signed with Ed25519. The canonical payload is a deterministic JSON string of the receipt fields (sorted keys), excluding the signature itself.

**Signed receipt fields (canonicalized):**
```
{ decision, decisionId, kernelBuild, nonce, policyHash, policyVersion, reason, timestamp }
```

**Signing flow:**
1. Serialize the 8 fields above as sorted-key JSON
2. Sign the UTF-8 bytes with Ed25519 private key
3. Encode signature as hex (128 characters)

**CLI verification:**
```bash
arikernel verify-receipt receipt.json --public-key <hex-encoded-public-key>
```

This verifies:
- All required fields are present
- Ed25519 signature is valid (if public key provided)
- Nonce and signature format are correct

**Programmatic verification:**
```typescript
import { DecisionVerifier, NonceStore } from "@arikernel/control-plane";

const verifier = new DecisionVerifier(publicKeyHex);
const nonces = new NonceStore();

// Verify signature + check nonce freshness
const valid = verifier.verify(response, nonces);
```

## Deployment Trust Model

```
┌─────────────────────────────────────────────────┐
│                  Trust Boundary                  │
│                                                  │
│  Control Plane (trusted)                         │
│    - Holds Ed25519 private key                   │
│    - Evaluates policy                            │
│    - Signs every decision                        │
│    - Maintains global taint registry             │
│    - Records audit trail                         │
│                                                  │
├──────────────────────────────────────────────────┤
│                                                  │
│  Sidecars (semi-trusted)                         │
│    - Hold Bearer auth token                      │
│    - Hold public key for verification            │
│    - Enforce decisions locally                   │
│    - Fail-closed when CP unreachable             │
│                                                  │
├──────────────────────────────────────────────────┤
│                                                  │
│  Agents (untrusted)                              │
│    - Tool calls intercepted by sidecar           │
│    - Cannot bypass enforcement for mediated calls │
│    - Cannot forge decision receipts              │
│                                                  │
└──────────────────────────────────────────────────┘
```

Key trust properties:
- **Non-repudiation**: Every decision is signed; the control plane cannot deny having made it
- **Tamper evidence**: Modifying any receipt field invalidates the Ed25519 signature
- **Replay resistance**: Request nonces prevent duplicate processing; response nonces prevent replay attacks
- **Policy binding**: `policyHash` in the receipt cryptographically binds the decision to the specific policy version evaluated
- **Fail-closed**: Sidecars deny tool calls when the control plane is unreachable

## Sidecar Integration

Set `decisionMode: "remote"` in the sidecar config to delegate policy decisions to the control plane.

```typescript
import { SidecarServer } from "@arikernel/sidecar";

const sidecar = new SidecarServer({
  preset: "safe",
  decisionMode: "remote",
  controlPlaneUrl: "http://localhost:9090",
  controlPlaneAuthToken: "shared-secret",
  controlPlaneTimeoutMs: 5000,
  controlPlanePublicKey: "<64-hex-char-ed25519-public-key>",
});
```

**Receipt verification:** When `controlPlanePublicKey` is configured, the sidecar verifies the Ed25519 signature and response nonce on every decision receipt before trusting it. Invalid signatures, tampered fields, and replayed nonces all cause fail-closed denial. Strongly recommended for production deployments.

**Fail-closed behavior:** The sidecar returns HTTP 503 and does not execute the tool call when:
- The control plane is unreachable within the timeout window
- Receipt signature verification fails (when public key is configured)
- A replayed response nonce is detected

## Deployment

### Single-node (development)

```typescript
import { ControlPlaneServer, generateSigningKey } from "@arikernel/control-plane";

const server = new ControlPlaneServer({
  signingKey: generateSigningKey(),
  policy: "./policies/safe-defaults.yaml",
  authToken: "dev-secret",
  port: 9090,
});
await server.listen();
console.log(`Public key: ${server.publicKeyHex}`);
console.log(`Policy hash: ${server.policyHash}`);
```

### Multi-sidecar (production)

1. Generate an Ed25519 signing key: `generateSigningKey()` returns a 64-char hex seed
2. Store the seed securely (environment variable, secrets manager)
3. Start the control plane with the signing key and YAML policies
4. Configure each sidecar with `decisionMode: "remote"` and the control plane URL
5. Distribute the public key (`server.publicKeyHex`) to clients for signature verification

```
┌─────────────────────────────────┐
│         Control Plane           │
│  signingKey: $CP_SIGNING_KEY    │
│  policy: /etc/ari/policies.yaml │
│  authToken: $CP_AUTH_TOKEN      │
│  auditLog: /var/lib/ari/cp.db   │
│  port: 9090                     │
└─────────────┬───────────────────┘
              │
     ┌────────┼────────┐
     │        │        │
  Sidecar   Sidecar  Sidecar
  :8787     :8788    :8789
```

### Environment variables

| Variable | Description |
|----------|-------------|
| `CP_SIGNING_KEY` | 64-char hex Ed25519 seed |
| `CP_AUTH_TOKEN` | Bearer token for sidecar authentication |
| `CP_POLICY_PATH` | Path to YAML policy file |
| `CP_AUDIT_LOG` | Path to SQLite audit database |
| `CP_PORT` | Listen port (default: 9090) |

## Global Taint Registry

The control plane maintains a cross-agent taint registry. When Agent A contaminates a shared resource (file, URL, database table), the control plane tracks this. When Agent B later makes a request touching that resource, the control plane enriches the request's taint labels with Agent A's contamination data before evaluating policies.

This enables detection of cross-agent relay attacks without requiring sidecars to share state directly.

## Audit Log

All decisions are stored in a SQLite database with the following schema:

| Column | Description |
|--------|-------------|
| `principal_id` | Who made the request |
| `tool_class` | Tool type (http, file, shell, etc.) |
| `action` | Action attempted |
| `decision` | Verdict (allow, deny, require-approval) |
| `reason` | Why the decision was made |
| `timestamp` | When the decision was made |
| `policy_version` | Policy version used |
| `run_id` | Run correlation ID |
| `signature` | Ed25519 signature for tamper evidence |

Query the audit log programmatically:

```typescript
server.audit.queryRecent(100);
server.audit.queryByPrincipal("agent-1");
```

### Audit Export

Export the audit log as JSONL for external analysis:

```bash
arikernel control-plane export-audit --db ./control-plane-audit.db --out audit.jsonl
```

Or programmatically:

```typescript
const jsonl = server.audit.exportJsonl();
```

Each line is a JSON object with the full audit row.

## Performance

The control plane targets sub-50ms decision latency. Key design choices:
- In-memory policy engine (no disk I/O on the decision path)
- In-memory taint registry (no database queries during evaluation)
- In-memory nonce store for replay protection
- WAL-mode SQLite for non-blocking audit writes
- Ed25519 signing (~microseconds per signature)
