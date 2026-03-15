# Changelog

All notable changes to Ari Kernel are documented here.
Versions are listed newest-first. For the initial release, see [0.1.0](#010--2026-03-05).

---

## [0.1.10] — 2026-03-15

### Security Hardening
- **Sidecar receipt verification**: `DecisionDelegate` now verifies Ed25519 signatures and response nonces on every control-plane decision receipt when `controlPlanePublicKey` is configured. Invalid signatures, tampered fields, and replayed nonces cause fail-closed denial.
- Added `controlPlanePublicKey` config to `SidecarConfig` and `RemoteDecisionConfig`
- `RemoteDecision` interface now includes `decisionId`, `policyHash`, and `kernelBuild` fields
- Wired existing `DecisionVerifier` and `NonceStore` from `@arikernel/control-plane` into the sidecar
- **HTTP GET/HEAD body rejection**: `HttpExecutor` now rejects GET/HEAD requests carrying a request body (RFC 9110 §9.3.1/§9.3.2). Bodies on bodyless methods are a semantic violation and a potential exfiltration vector.
- **Custom header exfiltration prevention**: After a confirmed sensitive file read, GET/HEAD requests with non-standard headers (X-*, custom) are denied. Standard browser headers (Accept, User-Agent, Cache-Control, etc.) remain allowed. Prevents secret smuggling via custom header values.
- Exported `SAFE_GET_HEADERS` allowlist from `@arikernel/tool-executors` for reuse in pipeline enforcement
- **Persistent taint stability**: `PersistentTaintRegistry` now keys by `principal.name` (stable caller-supplied identity) instead of the random per-run `principal.id` (ULID). Two Firewall instances for the same logical principal now correctly share cross-run security state.
- **Sidecar persistent taint**: `PrincipalRegistry.getOrCreate()` now enables persistent taint by default, so sidecar-managed principals inherit sticky flags across restarts

### Benchmark Scenarios (4 new)
- `de_get_header_exfil`: Verifies custom header exfiltration on GET is blocked after sensitive file read (behavioral enforcement)
- `de_get_body_exfil`: Verifies body on GET/HEAD is rejected by HttpExecutor per RFC 9110 (executor enforcement)
- `remote_decision_mitm_allow`: Verifies forged/tampered/replayed control-plane decisions are rejected by Ed25519 signature verification
- `fs_symlink_parent_escape`: Verifies parent-directory symlink escape is blocked before file creation side-effect (realpath validation)
- 3 YAML attack-sim scenarios added: `http-get-header-exfiltration`, `http-get-body-exfiltration`, `symlink-parent-write-escape`
- Benchmark suite expanded from 18 to 22 scenarios; attack-sim suite expanded from 10 to 13

## [0.1.9] — 2026-03-13

### Added
- **Persistent TokenStore**: SQLite-backed grant storage — tokens survive sidecar restarts. Each principal gets a dedicated `{name}-tokens.db` alongside its audit DB. Same LRU eviction and TTL behavior as the in-memory store.
- **TLS support**: `--tls-cert` and `--tls-key` CLI flags enable HTTPS on the sidecar. Recommended for non-localhost deployments where agent and sidecar are in separate containers.
- `ITokenStore` interface for pluggable token store implementations
- `SqliteTokenStore` class exported from `@arikernel/runtime`
- Python integration tests now use a local HTTP server fixture instead of external URLs (httpbin.org, example.com) for offline CI stability

### Fixed
- Scoped "cannot bypass" claims in README, ARCHITECTURE.md, and control-plane docs to "for mediated calls" — aligns with NIST reference monitor framing

## [0.1.8] — 2026-03-12

### Security Hardening
- **Sidecar `/execute` protocol**: Decoupled `allowed` (policy verdict) from `success` (executor outcome); added `grantId` support with precedence (`capabilityToken` > `grantId` > auto-issue)
- **Sensitive-read confirmation**: Sticky flag now requires `file.read` action AND `result.success` — failed reads and writes no longer set `sensitiveReadObserved`
- **SSRF: IPv4-mapped IPv6 hex form**: `normalizeIP()` now detects `::ffff:HHHH:HHHH` hex-encoded mapped addresses (e.g. `::ffff:7f00:1` → 127.0.0.1)
- **SSRF: numeric IPv4 hostnames**: `resolveHost()` blocks decimal (`2130706433`) and hex (`0x7f000001`) integer encodings of private IPs before DNS lookup
- **`content-scan` untrusted source**: Added to `UNTRUSTED_SOURCES` in capability issuer; DLP-detected content now blocks sensitive capability issuance
- **`user-provided` naming fix**: Corrected `user-input` → `user-provided` to match `TaintSource` enum

### Fixed
- **SharedTaintRegistry bounded growth**: TTL expiry (default 1 hour) and max-entries cap (default 10,000) with LRU eviction prevent unbounded memory growth
- **TokenStore bounded growth**: Configurable `maxSize` (default 10,000) with LRU eviction replacing fixed 100-entry threshold; evicts expired first, then oldest active
- **FirewallClient deprecated**: Runtime `DeprecationWarning` emitted on instantiation; directs users to `SidecarKernel`/`create_kernel()`

### Added
- Python integration test for allowed-but-failed semantics (`verdict=allow`, `success=false`)
- Python sidecar semantics unit tests (mock-based, no sidecar required)
- 23 SSRF regression tests for hex-form mapped IPv6 and numeric IPv4 hostname bypass vectors
- `setUntrustedSources()` / `getUntrustedSources()` for runtime-configurable untrusted taint source list

## [0.1.7] — 2026-03-11

### Security Hardening
- **F-07**: Sticky escalation denial flag on `RunStateTracker` — Rule 2 (`denied_capability_then_escalation`) now persists across event window eviction, preventing attackers from spacing denial and escalation steps across >20 events to avoid detection
- **F-06**: Model-generated taint injection — all tool call requests originating from LLM output now carry `source: "model-generated"` taint labels, injected at pipeline entry before policy evaluation
- **F-09**: NFKC normalization in AutoScope — `classifyScope()` now normalizes input via `normalizeInput()` before keyword matching, preventing homoglyph and zero-width character bypass of scope classification

### Fixed
- **F-11**: `require-approval` policy verdict now emits `console.warn` when no `onApprovalRequired` handler is registered, making silent denials visible in logs
- Scenario-runner test counts updated to match actual 10 built-in YAML scenarios

## [0.1.6] — 2026-03-11

### Added
- **Decision replay protection**: Control plane rejects duplicate `requestNonce` values with HTTP 409, preventing request replay attacks
- **Policy versioning and receipts**: Every decision response now includes `decisionId`, `policyHash` (SHA-256 prefix), `policyVersion`, and `kernelBuild` — all signed into the Ed25519 receipt
- **`arikernel verify-receipt`**: CLI command to verify Ed25519 signature, required fields, and payload integrity of decision receipts
- **`arikernel control-plane export-audit`**: Export control plane audit logs in JSONL format for external analysis
- **`arikernel compliance-report`**: Generate compliance/evidence reports in human-readable, JSON, or Markdown format — covers deployment mode, policy state, security protections, benchmark coverage, and attack simulation availability
- `ControlPlaneAuditStore.exportJsonl()` and `queryAll()` methods
- `ControlPlaneServer.policyHash` getter
- `docs/compliance-reporting.md` documentation
- Updated `docs/control-plane.md` with replay protection, signed receipts, trust model, and audit export sections

## [0.1.5] — 2026-03-10

### Security Hardening
- **Low-entropy exfiltration eliminated**: Post-sensitive-read quarantine GET budget reduced to 0 — all parameterized GETs are blocked after sensitive file reads in quarantine mode
- **Cumulative egress accounting**: RunStateTracker now tracks total outbound query-string bytes per hostname per run, enabling detection of chunked exfiltration across multiple small requests
- **Low-entropy encoding detection**: New `hasEncodedPayload()` detector identifies base64 and hex-encoded data in query parameter values, blocking encoded exfil chunks in quarantine
- **Hostname risk context**: `egressAllowHosts` policy option exempts known-safe hostnames from post-sensitive-read egress tightening

### Fixed
- Low-entropy exfiltration benchmark now returns BLOCKED instead of PARTIAL — quarantine no longer allows 3 parameterized GETs after sensitive reads

## [0.1.4] — 2026-03-10

### Security Hardening
- **Canonicalized shared resource keys**: SharedTaintRegistry and CrossPrincipalCorrelator now normalize file paths (NFKC + resolve) and database identifiers (lowercase) to prevent case/path mismatch bypass in cross-principal taint tracking
- **Structured database parameters required**: DatabaseExecutor (MVP stub) rejects calls without explicit `table` field, preventing shared-store taint tracking bypass. The executor validates and audits but does not connect to real databases.
- **CP-3 noise reduction**: Added `cp3.allowHosts`, `cp3.suppressHosts`, and `cp3.dedupeWindowMs` config to reduce false positives on shared APIs; enriched CP-3 alerts with hostname and sensitive-read metadata
- **Safe-regex validation at policy load**: Policy rules with nested-quantifier regex patterns (ReDoS risk) are rejected at load time via `validatePolicyRegexSafety()`
- **Recursive DLP scanning**: Output filter now traverses nested objects, arrays, and structured tool results — not just top-level strings
- **FILE_EXECUTOR_ROOT warning**: FileExecutor emits a console warning when FILE_EXECUTOR_ROOT is not explicitly set, flagging cwd-default as a production misconfiguration risk
- **Quarantine-on-alert**: CP correlator alerts (CP-1/CP-2/CP-3) can now auto-quarantine all offending principals via `quarantineOnAlert: true` config

### Fixed
- Cross-principal taint tracking failed when agents used different path representations (e.g. `./data/file` vs `/abs/data/file`) or case variations in table names
- DLP output filter missed secrets embedded in nested JSON objects or arrays

### Added
- `Firewall.quarantineExternal()` public method for external quarantine triggers
- `CP3Config` interface with allow/suppress host lists and configurable dedup window
- `checkRegexSafety()` and `validatePolicyRegexSafety()` exports from policy-engine
- Identity binding modes documented in sidecar-mode.md (dev mode vs authenticated mode)
- Capability token usage documented on `/execute` endpoint

## [0.1.3] — 2026-03-09

### Fixed
- Unknown capability classes (e.g. `email.write`) now fail closed with a denial instead of crashing with TypeError
- `requestCapability()` validates against `CAPABILITY_CLASS_MAP` before proceeding
- LangChain middleware preserves `this` binding when wrapping tool functions
- Denied tool calls produce structured `ToolCallDeniedError` with valid fields (no `as any` casts)
- Policy spec loaded via inline JSON import instead of runtime filesystem traversal

### Added
- `autoTaint` middleware option — derives taint labels from tool parameters in stub executors
- GitHub Actions CI with TypeScript build/test/lint, Python pytest, and npm pack smoke test
- Audit log anchor hash (`start_previous_hash`) for cross-run chain continuity verification
- `verifyDatabaseChain()` for whole-database integrity validation
- `deriveCapabilityClass()` using inverse `CAPABILITY_CLASS_MAP` lookup
- Decision server hardening: localhost binding, bearer auth, body size limit, rate limiting
- Security presets: `safe`, `strict`, `research`, `safe-research`, `rag-reader`, `workspace-assistant`, `automation-agent`
- `require-approval` policy verdict with fail-closed default
- Python adapter with `@protect_tool` decorator and framework wrappers

### Changed
- CI job renamed from `ci` to `typescript` + separate `python` job
- Middleware taint boundary docs clarified with `autoTaint` option

## [0.1.2] — 2026-03-07

### Added
- Deterministic forensic pipeline: `simulate`, `trace`, `replay` share same audit database
- `--db` flag on all forensic CLI commands
- LangChain integration example at `examples/langchain-protected-agent/`
- Framework adapters: `protectTools()`, `protectOpenAITools()`, `LangChainAdapter`, `CrewAIAdapter`, `protectVercelTools()`

---

## [0.1.0] — 2026-03-05 — Initial Release

### Important: Release Scope

> **v0.1.0 is a TypeScript / Node.js release.** The Python runtime (`python/`) is experimental and excluded from this release. Two release-blocking issues — `require-approval` semantic divergence and broken packaging/spec discovery — are tracked for a future release.

### Security Features
- **Capability token system** — time-limited (5 min), usage-limited (10 calls), scope-constrained grants with atomic token validation; no ambient authority
- **Taint tracking with auto-propagation** — data provenance labels (`web`, `rag`, `email`) auto-attached by HTTP, RAG, and MCP executors; propagated through tool chains; model-generated taint injection at pipeline entry
- **Policy engine** — priority-sorted YAML rules with deny-by-default; taint-conditioned matching; safe-regex validation at load time (ReDoS prevention)
- **Behavioral sequence detection** — 6 built-in rules (`web_taint_sensitive_probe`, `denied_capability_then_escalation`, `sensitive_read_then_egress`, `tainted_database_write`, `tainted_shell_with_data`, `secret_access_then_any_egress`) operating on a 20-event sliding window with sticky flags that survive window eviction
- **Run-level quarantine** — irrecoverable restricted mode; once triggered, the run is locked to read-only for its remainder
- **Persistent cross-run taint registry** — SQLite-backed taint events survive process restarts; sticky flags propagate across run boundaries via seeder methods; prevents split-run attacks
- **Cross-principal correlator** — CP-1 (shared resource contamination), CP-2 (taint relay chain), CP-3 (egress convergence) alerts with optional auto-quarantine
- **Ed25519 signed decision receipts** — every control plane decision includes `decisionId`, `policyHash`, `policyVersion`, `kernelBuild`, `nonce`, and cryptographic signature; verifiable with public key only
- **Nonce-based replay protection** — control plane rejects duplicate `requestNonce` values (HTTP 409); sidecar `DecisionDelegate` generates per-request nonces via `crypto.randomBytes`
- **Enforcement mode production guards** — sidecar and control plane throw at startup when `NODE_ENV=production` and required configuration (principals, authToken) is missing
- **SHA-256 hash-chained audit log** — tamper-evident event store with cross-run anchor hashes and JSONL export

### Added
- SSRF protection with private IP blocking and redirect validation
- Symlink protection via `realpathSync()` with path canonicalization
- Output filtering (DLP) with bounded-quantifier secret pattern detection and recursive nested-object scanning
- CLI: `simulate`, `trace`, `replay`, `replay-trace`, `sidecar`, `policy`, `attack simulate`, `compliance-report`, `verify-receipt`, `control-plane export-audit` commands
- Sidecar HTTP proxy mode with per-principal isolation, bearer token auth, rate limiting, body size limits
- 8 security presets: `safe`, `strict`, `research`, `safe-research`, `rag-reader`, `workspace-assistant`, `automation-agent`, `anti-collusion`
- Framework middleware: LangChain, OpenAI Agents SDK, CrewAI, AutoGen wrappers
- MCP tool integration via `protectMCPTools()`
- Python runtime with `@protect_tool` decorator **(experimental — not part of v0.1.0 release scope)**
