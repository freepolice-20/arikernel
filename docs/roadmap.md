# Roadmap

> See also: [Architecture](../ARCHITECTURE.md) | [Security Model](security-model.md)

## Completed

- [x] Core domain types and Zod validation schemas
- [x] Policy engine with YAML loading, priority-sorted first-match-wins evaluation
- [x] Taint tracker with label creation, propagation, and querying
- [x] Auto-taint from HTTP and RAG tool outputs
- [x] Audit log with SQLite storage and SHA-256 hash chain verification
- [x] Tool executors for HTTP (with SSRF protection), file (with symlink protection), shell (with command validation)
- [x] Runtime pipeline: validate → run-state check → token check → taint collect → policy evaluate → execute → propagate → audit → behavioral rules
- [x] Capability issuance with lease-based tokens (5 min TTL, 10 calls)
- [x] Grant constraint enforcement (allowed hosts, paths, commands, databases)
- [x] Path canonicalization and traversal prevention
- [x] Shell command validation with metacharacter blocking
- [x] Behavioral sequence detection (6 built-in rules)
- [x] Run-level quarantine (behavioral + threshold triggers)
- [x] Security presets (safe-research, rag-reader, workspace-assistant, automation-agent)
- [x] AutoScope for automatic preset selection
- [x] Framework adapters: OpenAI, OpenAI Agents SDK, LangChain, LlamaIndex TS, CrewAI, Vercel AI, MCP, OpenClaw (experimental); AutoGen (Python) and AutoGPT (Python) are experimental — not in v0.1.0
- [ ] ~~Native Python runtime with same enforcement model~~ — **deferred from v0.1.0** (experimental; `require-approval` semantic divergence and packaging issues block release)
- [x] Sidecar / proxy mode with per-principal isolation, status endpoint, capability grants
- [x] CLI: init, policy validate, simulate, trace, replay, replay-trace, sidecar
- [x] Deterministic trace recording and replay with what-if analysis
- [x] AgentDojo-aligned benchmark harness (5 scenarios)
- [x] SSRF protection (private IP blocking, redirect validation)
- [x] Output filtering / DLP (secret pattern detection)
- [x] Monorepo with pnpm workspaces, Turborepo, tsup builds, Biome linting

## Next Milestone: Hardening

These are the most valuable next steps. Not all will be built — this is a prioritized list.

**Persistent TokenStore.** Replace the in-memory Map with SQLite or Redis-backed storage so grants survive process restarts. Required for any production use.

**Constraint composition.** Merge grant constraints with policy constraints at evaluation time. Currently they are checked independently; the intersection should be enforced.

**Rate limiting.** Add per-principal and per-capability-class rate limits to prevent abuse through rapid token re-issuance.

**Dynamic policy reload.** Watch YAML policy files for changes and reload without restarting the kernel process.

**Database executor.** Implement the real database executor with parameterized query support and SQL injection prevention.

**Sidecar hardening.** TLS, authentication, connection pooling, graceful shutdown for production sidecar deployments.

**More tests.** Integration tests for the full pipeline. Fuzzing for constraint bypass. Expanded benchmark coverage.

## Out of Scope (For Now)

These are explicitly not planned for the near term:

- **Web dashboard or UI** — Ari Kernel is a library and CLI tool
- **Multi-tenant / multi-process** — the current model is single-process; distributed token validation is a future concern
- **LLM-layer defenses** — prompt hardening, output filtering, and model-level safety are orthogonal to runtime enforcement
