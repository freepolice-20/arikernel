# Roadmap

> See also: [Architecture](../ARCHITECTURE.md) | [Security Model](security-model.md)

## Completed

- [x] Core domain types and Zod validation schemas
- [x] Policy engine with YAML loading, priority-sorted first-match-wins evaluation
- [x] Taint tracker with label creation, propagation, and querying
- [x] Auto-taint from HTTP and RAG tool outputs
- [x] Audit log with SQLite storage and SHA-256 hash chain verification
- [x] Tool executors for HTTP, file, shell (database is a stub)
- [x] Runtime pipeline: validate → token check → taint collect → policy evaluate → execute → propagate → audit
- [x] Capability issuance with lease-based tokens (5 min TTL, 10 calls)
- [x] Grant constraint enforcement (allowed hosts, paths, commands, databases)
- [x] Path canonicalization and traversal prevention
- [x] Shell command validation with metacharacter blocking
- [x] Behavioral sequence detection (3 built-in rules)
- [x] Run-level quarantine (behavioral + threshold triggers)
- [x] Security presets (safe-research, rag-reader, workspace-assistant, automation-agent)
- [x] AutoScope for automatic preset selection
- [x] Framework adapters: OpenAI, OpenAI Agents SDK, LangChain, LlamaIndex TS, CrewAI, Vercel AI, MCP, AutoGen (Python), AutoGPT (Python)
- [x] Native Python runtime with same enforcement model
- [x] Sidecar / proxy mode (experimental)
- [x] CLI: init, policy validate, simulate, trace, replay
- [x] AgentDojo-aligned benchmark harness (5 scenarios)
- [x] Monorepo with pnpm workspaces, Turborepo, tsup builds, Biome linting

## Next Milestone: Hardening

These are the most valuable next steps. Not all will be built — this is a prioritized list.

**Persistent TokenStore.** Replace the in-memory Map with SQLite or Redis-backed storage so grants survive process restarts. Required for any production use.

**Constraint composition.** Merge grant constraints with policy constraints at evaluation time. Currently they are checked independently; the intersection should be enforced.

**Rate limiting.** Add per-principal and per-capability-class rate limits to prevent abuse through rapid token re-issuance.

**Dynamic policy reload.** Watch YAML policy files for changes and reload without restarting the kernel process.

**Database executor.** Implement the real database executor with parameterized query support and SQL injection prevention.

**Sidecar hardening.** Production-harden the sidecar proxy: TLS, authentication, connection pooling, graceful shutdown.

**More tests.** Integration tests for the full pipeline. Fuzzing for constraint bypass. Expanded benchmark coverage.

## Out of Scope (For Now)

These are explicitly not planned for the near term:

- **Web dashboard or UI** — Ari Kernel is a library, not a SaaS product
- **Multi-tenant / multi-process** — the current model is single-process; distributed token validation is a future concern
- **LLM-layer defenses** — prompt hardening, output filtering, and model-level safety are orthogonal to runtime enforcement
- **Commercial licensing** — the project is Apache-2.0 and will stay open-source
