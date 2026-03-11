# Changelog

All notable changes to Ari Kernel are documented here.

## [0.1.4] — 2026-03-10

### Security Hardening
- **Canonicalized shared resource keys**: SharedTaintRegistry and CrossPrincipalCorrelator now normalize file paths (NFKC + resolve) and database identifiers (lowercase) to prevent case/path mismatch bypass in cross-principal taint tracking
- **Structured database parameters required**: DatabaseExecutor rejects raw SQL queries without explicit `table` field, preventing shared-store taint tracking bypass
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

## [0.1.0] — 2026-03-05

### Added
- Initial release
- Capability token system with time/usage/scope limits
- Taint tracking with auto-propagation
- Policy engine with YAML-defined rules
- Behavioral sequence detection (6 built-in rules)
- Run-level quarantine with irrecoverable restricted mode
- SHA-256 hash-chained audit log
- SSRF protection with private IP blocking and redirect validation
- Symlink protection via `realpathSync()`
- Output filtering (DLP) with secret pattern detection
- CLI: `simulate`, `trace`, `replay`, `sidecar`, `policy` commands
- Sidecar HTTP proxy mode on port 8787
