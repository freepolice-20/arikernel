# Security Evaluation Response

This document tracks findings from internal security audits and red-team exercises, their resolution status, and the implementing fix.

## Findings Summary

| Original Finding | Status | Fix |
|---|---|---|
| Middleware taint gap | Resolved | `observeToolOutput` pipeline — adapters feed real tool output back for content scanning and taint derivation |
| Sliding window evasion | Resolved | Sticky behavioral flags (`sensitiveReadObserved`, `egressObserved`, `secretAccessObserved`) survive 20-event window eviction |
| Unicode obfuscation | Resolved | NFKC normalization at all security input boundaries (paths, commands, shell, run-state sensitive path detection) |
| Cross-agent collusion | Mitigated | Shared-store taint (`derived-sensitive`), `CrossPrincipalCorrelator` (alerting), `anti-collusion` preset with explicit deny policies; wired into sidecar runtime via `onAudit` hooks per principal |
| Slow drip GET exfiltration | Resolved | Quarantine GET budget — sensitive-read-then-GET-with-params treated as egress, 3-request cap post-quarantine |
| `http.write` not taint-gated | Resolved | Added `http.write` to `sensitiveClasses` in capability issuer |
| Command path trust | Resolved | Binary path validation against `TRUSTED_PATH_PREFIXES`; untrusted paths rejected |
| Path canonicalization fallback | Resolved | Fail-closed on canonicalization error — throws instead of returning un-canonicalized path |
| Non-TLS sidecar warning | Resolved | Runtime warning when sidecar endpoint is non-localhost and non-HTTPS |
| Nonce replay scope | Resolved | Nonce replay detection code removed — `maxCalls`/`consume()` is the replay prevention mechanism; nonce retained only for token signing integrity |
| Error message leakage | Resolved | Router 500 responses return generic `"Internal server error"` instead of raw error messages |
| Response body unbounded | Resolved | 10 MB response body limit in SSRF handler; connection destroyed on exceed |
| Shell env leakage | Resolved | Environment sanitized before spawn (strips SECRET/TOKEN/KEY/PASSWORD/AUTH vars); `env`/`printenv`/`set` blocked |
| Nonce set memory growth | Resolved | Dead nonce tracking code removed — no in-memory nonce set |
| Timing-safe comparison | Resolved | Replaced custom implementation with `crypto.timingSafeEqual` from Node.js stdlib |
| Unicode regex missing global flag | Resolved | Split into `DANGEROUS_UNICODE_DETECT` (non-global for `.test()`) and `DANGEROUS_UNICODE_STRIP` (global for `.replace()`) |
| `secureExecute()` wrong capability class | Resolved | Replaced ad-hoc string heuristic with canonical `deriveCapabilityClass()` — fixes shell.exec, database.query mappings |
| Nonce makes grants single-use | Resolved | Removed per-grant nonce check from pipeline `validateToken()` — `consume()` with `callsUsed`/`maxCalls` is the correct use-limiting mechanism |
| File write TOCTOU with O_TRUNC | Resolved | Write path now opens WITHOUT `O_TRUNC`, validates (fstat + realpath root containment), then truncates — matching read-path security model |
| Cross-principal taint/correlator not wired | Resolved | `PrincipalRegistry.getOrCreate()` now passes `onAudit` hook that feeds correlator and shared-taint registry per principal |
| Pipeline pre-decision event misclassification | Resolved | Removed premature `tool_call_allowed` events for shell/database before policy decision; post-decision event at step 6.5 is authoritative |
| GET path-segment exfiltration | Resolved | Path segment entropy analysis (Shannon entropy > 0.7 on segments ≥ 32 chars) detects base64/hex encoded data in URL paths |
| Correlator not resource-key aware | Resolved | CP-1 rule now correlates on canonical resource keys (`db:<table>`, `file:<path>`) — write and read must target the same resource |
| Correlator reading wrong AuditEvent fields | Resolved | Fixed to read from nested `event.toolCall.*` instead of non-existent top-level fields |
| Security claims not scoped | Resolved | SECURITY.md now documents NIST reference monitor compliance per mode, ambient authority limitations, egress model limitations, and non-goals |

## Accepted Risks

| Finding | Risk Level | Rationale |
|---|---|---|
| Policy engine path/command checks weaker than grant-level | Low | Defense-in-depth — grant-level checks in pipeline.ts are fully hardened with canonicalization and unicode normalization |
| Rate limits default to unlimited | Low | Dev-mode default; localhost-only binding; production deployments configure explicit limits |
| No auth without explicit config | Low | Dev-mode behavior; localhost-only; documented in security model |
| Client-supplied taint labels | Low | Supplementary only — kernel tracks taint independently via sticky flags and content scanning |
| Event window size fixed at 20 | Low | Sticky flags counter window evasion; configurable window is a future enhancement |
| Cross-agent collusion not fully prevented | Medium | Lightweight provenance, not full prevention — documented scope limitation; correlator provides alerting for operational response |

## Test Coverage

749 tests passing across all packages. Security-specific test files:

- `packages/runtime/__tests__/sticky-state-hardening.test.ts` — window evasion attacks
- `packages/runtime/__tests__/unicode-safety.test.ts` — NFKC normalization and dangerous unicode detection
- `packages/runtime/__tests__/command-security-h4.test.ts` — binary path validation
- `packages/runtime/__tests__/issuer-h2.test.ts` — http.write taint denial
- `packages/runtime/__tests__/slow-drip-exfil.test.ts` — quarantine GET budget
- `packages/runtime/__tests__/path-security.test.ts` — traversal, symlink, fail-closed
- `packages/runtime/__tests__/security/regression.test.ts` — constraint intersection, token TOCTOU, ReDoS, regex fail-closed, token replay semantics, GET path-segment exfil, unicode global stripping
- `packages/sidecar/__tests__/shared-taint-registry.test.ts` — shared-store contamination tracking
- `packages/sidecar/__tests__/correlator.test.ts` — cross-principal alert correlation
- `packages/core/__tests__/presets-anti-collusion.test.ts` — anti-collusion preset validation
- `packages/tool-executors/__tests__/shell-unicode.test.ts` — shell unicode bypass prevention
