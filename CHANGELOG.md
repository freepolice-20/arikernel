# Changelog

All notable changes to Ari Kernel are documented here.

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
