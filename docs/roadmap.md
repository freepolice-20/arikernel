# Roadmap

## Completed (MVP)

- [x] Core domain types and Zod validation schemas
- [x] Policy engine with YAML loading, priority-sorted first-match-wins evaluation
- [x] Taint tracker with label creation, propagation, and querying
- [x] Audit log with SQLite storage and SHA-256 hash chain verification
- [x] Tool executors for HTTP, file, shell (database is a stub)
- [x] Runtime pipeline: validate → token check → taint collect → policy evaluate → execute → propagate → audit
- [x] Capability issuance: request → principal check → action check → taint risk assessment → policy check → grant with lease
- [x] Token lifecycle: issuance, validation, consumption, revocation, expiry
- [x] Mandatory token enforcement for all protected tool classes
- [x] Grant constraint enforcement (allowed hosts, paths, commands, databases)
- [x] Principal-bound tokens (grant principal must match caller)
- [x] Four runnable demos: core pipeline, capability issuance, prompt injection attack, capability escalation
- [x] Runtime enforcement test suite (8 tests)
- [x] Monorepo with pnpm workspaces, Turborepo, tsup builds, Biome linting
- [x] CLI with init, policy validate, audit replay, and simulate commands

## Next Milestone: Hardening

These are the most valuable next steps. Not all will be built — this is a prioritized list.

**Persistent TokenStore.** Replace the in-memory Map with SQLite or Redis-backed storage so grants survive process restarts. Required for any production use.

**Automatic taint detection.** Instead of requiring callers to manually label taint sources, inspect tool call results and infer taint from content characteristics (URLs in output, email headers, RAG metadata).

**Constraint composition.** Merge grant constraints with policy constraints at evaluation time. Currently they are checked independently; the intersection should be enforced.

**Rate limiting.** Add per-principal and per-capability-class rate limits to prevent abuse through rapid token re-issuance.

**Dynamic policy reload.** Watch YAML policy files for changes and reload without restarting the firewall process.

**Database executor.** Implement the real database executor with parameterized query support and SQL injection prevention.

**More tests.** Unit tests for policy engine, taint tracker, audit log, and issuer. Integration tests for the full pipeline. Fuzzing for constraint bypass.

## Out of Scope (For Now)

These are explicitly not planned for the near term:

- **Web dashboard or UI** — AriKernel is a library, not a SaaS product
- **Multi-tenant / multi-process** — the current model is single-process; distributed token validation is a future concern
- **LLM-layer defenses** — prompt hardening, output filtering, and model-level safety are orthogonal to runtime enforcement
- **Agent framework integrations** — adapters for LangChain, CrewAI, AutoGen, etc. will be built once the core API stabilizes
- **Commercial licensing** — the project is Apache-2.0 and will stay open-source
- **Cloud-hosted version** — no hosted service is planned
