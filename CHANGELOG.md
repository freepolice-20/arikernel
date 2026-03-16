# Changelog

All notable changes to Ari Kernel are documented here.

## [0.1.0] — 2026-03-15 — Initial Release

> **v0.1.0 is a TypeScript / Node.js release.** The Python runtime (`python/`) is experimental and excluded from this release.

### Security

- **Capability token system** — time-limited, usage-limited, scope-constrained grants with atomic validation; no ambient authority. Persistent SQLite-backed token store survives sidecar restarts with LRU eviction and TTL expiry.
- **Taint tracking with auto-propagation** — data provenance labels (`web`, `rag`, `email`, `model-generated`, `user-provided`, `content-scan`) auto-attached by executors and injected at pipeline entry; propagated through tool chains with NFKC-normalized resource keys for cross-principal consistency.
- **Persistent cross-run taint registry** — SQLite-backed taint events keyed by stable principal name; sticky flags propagate across run boundaries and process restarts, preventing split-run attacks.
- **Policy engine** — priority-sorted YAML rules with deny-by-default, taint-conditioned matching, and safe-regex validation at load time (ReDoS prevention via nested-quantifier rejection).
- **Behavioral sequence detection** — 6 built-in rules operating on a 20-event sliding window with sticky flags that survive window eviction, covering sensitive-read-then-egress, denied-capability-then-escalation, tainted database writes, secret access patterns, and more.
- **Run-level quarantine** — irrecoverable restricted mode locks a run to read-only; triggerable by policy, behavioral detection, or cross-principal correlator alerts.
- **Cross-principal correlator** — CP-1 (shared resource contamination), CP-2 (taint relay chain), CP-3 (egress convergence) alerts with configurable allow/suppress host lists, dedup windows, and optional auto-quarantine.
- **Ed25519 signed decision receipts** — every control plane decision includes `decisionId`, `policyHash`, `policyVersion`, `kernelBuild`, nonce, and cryptographic signature; sidecar verifies signatures and rejects tampered or replayed receipts fail-closed.
- **Nonce-based replay protection** — control plane rejects duplicate request nonces (HTTP 409); sidecar generates per-request nonces via `crypto.randomBytes`.
- **SSRF protection** — private IP blocking, redirect validation, IPv4-mapped IPv6 hex-form detection, and numeric IPv4 hostname blocking (decimal and hex encodings).
- **Symlink escape prevention** — `realpathSync()` path canonicalization blocks parent-directory symlink traversal before file operations.
- **HTTP method enforcement** — GET/HEAD requests with bodies are rejected per RFC 9110; custom header exfiltration is blocked after sensitive file reads while standard browser headers remain allowed.
- **Post-sensitive-read egress controls** — zero-budget quarantine on parameterized GETs after sensitive reads, cumulative per-hostname query-string byte accounting, and base64/hex encoded payload detection.
- **Output filtering (DLP)** — bounded-quantifier secret pattern detection with recursive nested-object and array scanning.
- **SHA-256 hash-chained audit log** — tamper-evident event store with cross-run anchor hashes, database chain verification, and JSONL export.
- **Enforcement mode production guards** — sidecar and control plane throw at startup when `NODE_ENV=production` and required configuration is missing.

### Added

- **CLI commands**: `simulate`, `trace`, `replay`, `replay-trace`, `sidecar`, `policy`, `attack simulate`, `compliance-report`, `verify-receipt`, `control-plane export-audit`.
- **Sidecar HTTP proxy mode** with per-principal isolation, bearer token auth, rate limiting, body size limits, and optional TLS (`--tls-cert`, `--tls-key`).
- **Control plane** with remote policy decisions, Ed25519 receipt signing, audit store with JSONL export, and policy versioning.
- **8 security presets**: `safe`, `strict`, `research`, `safe-research`, `rag-reader`, `workspace-assistant`, `automation-agent`, `anti-collusion`.
- **Framework middleware**: LangChain, OpenAI Agents SDK, CrewAI, Vercel AI SDK, and AutoGen adapters via `protectTools()` and framework-specific wrappers.
- **MCP tool integration** via `protectMCPTools()`.
- **`require-approval` policy verdict** with fail-closed default and console warning when no approval handler is registered.
- **`autoTaint` middleware option** for deriving taint labels from tool parameters in stub executors.
- **Compliance reporting** in human-readable, JSON, or Markdown format covering deployment mode, policy state, security protections, and benchmark coverage.
- **22 benchmark scenarios** and **13 attack simulation scenarios** covering exfiltration vectors, SSRF bypasses, symlink escapes, replay attacks, and behavioral detection.
- Deterministic forensic pipeline: `simulate`, `trace`, `replay` share the same audit database via `--db` flag.
- LangChain integration example at `examples/langchain-protected-agent/`.
- GitHub Actions CI with TypeScript build/test/lint, Python pytest, and npm pack smoke test.
- Python runtime with `@protect_tool` decorator **(experimental — not part of v0.1.0 release scope)**.

### Changed

- `Firewall.quarantineExternal()` public method enables external quarantine triggers (e.g., from correlator alerts).
- `FirewallClient` deprecated in favor of `SidecarKernel` / `create_kernel()`.
- Runtime-configurable untrusted taint source list via `setUntrustedSources()` / `getUntrustedSources()`.

### Fixed

- Unknown capability classes fail closed with denial instead of crashing.
- LangChain middleware preserves `this` binding when wrapping tool functions.
- Denied tool calls produce structured `ToolCallDeniedError` with valid fields.
- SharedTaintRegistry and TokenStore enforce bounded growth via TTL expiry and LRU eviction, preventing unbounded memory consumption.
- Cross-principal taint tracking handles path normalization and case variations correctly.
- Sensitive-read confirmation requires successful `file.read` — failed reads and writes no longer set the sticky flag.
