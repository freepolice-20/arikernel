# Remediation Summary

Post-review remediation status for Ari Kernel, prepared for external review handoff.

## Findings Fixed (14/14)

| ID | Severity | Title | Fix Summary |
|----|----------|-------|-------------|
| F-01 | HIGH | Capability tokens lack crypto binding | Ed25519-signed capability tokens with principal identity binding |
| F-02 | HIGH | No cross-principal taint propagation | SharedTaintRegistry + CrossPrincipalCorrelator with CP-1/CP-2/CP-3 alerts |
| F-03 | HIGH | Policy engine bypass via direct executor access | Sidecar mode enforces process isolation; documented enforcement boundaries |
| F-04 | MEDIUM | Behavioral rules use fixed window, no persistence | Sticky state flags survive event window eviction (Rules 1–6) |
| F-05 | MEDIUM | No rate limiting on tool calls | Per-principal rate limiting with configurable window/threshold |
| F-06 | MEDIUM | Model-generated content not tainted | `model-generated` taint injected at pipeline entry for all LLM tool calls |
| F-07 | MEDIUM | Rule 2 escalation detection resets on window eviction | Sticky `escalationDeniedObserved` flag on RunStateTracker with risk-aware tracking |
| F-08 | MEDIUM | Audit log lacks tamper evidence | Ed25519-signed decision receipts with `decisionId`, `policyHash`, `policyVersion` |
| F-09 | MEDIUM | AutoScope keyword matching bypassed by homoglyphs | NFKC normalization + zero-width character stripping in `classifyScope()` |
| F-10 | MEDIUM | No anti-collusion detection for multi-agent | CP-3 egress convergence detection; `quarantineOnAlert` auto-response |
| F-11 | LOW | Silent denial when no approval handler registered | `console.warn` emitted; action still denied by default |
| F-12 | LOW | No compliance/evidence reporting | `arikernel compliance-report` with human, JSON, and Markdown output |
| F-13 | LOW | Unicode normalization missing from shell commands | NFKC normalization in ShellExecutor command validation |
| F-14 | LOW | No request replay protection | Control plane rejects duplicate `requestNonce` values (HTTP 409) |

## Architectural Additions

| Component | Package | Purpose |
|-----------|---------|---------|
| Control Plane | `@arikernel/control-plane` | Centralized decision delegation, Ed25519 signing, audit export |
| Persistent Taint Registry | `@arikernel/runtime` | Cross-run taint tracking via file-backed storage |
| Decision Delegate | `@arikernel/sidecar` | Sidecar-to-control-plane decision forwarding |
| YAML Scenario Runner | `@arikernel/attack-sim` | Declarative attack scenarios with Zod-validated schema |
| Compliance Reporter | `@arikernel/cli` | Evidence generation for audits and certifications |
| Receipt Verifier | `@arikernel/cli` | Standalone Ed25519 receipt verification |

## Benchmark & Testing Summary

| Metric | Value |
|--------|-------|
| Total tests | 870 |
| Test files | 69 passing, 1 skipped |
| Failures | 0 |
| YAML attack scenarios | 10 (9 blocked by policy, 1 requires executor-level enforcement) |
| Programmatic attack scenarios | 23 (single-step) + 4 (multi-step) |
| Benchmark categories | 6 (prompt injection, SSRF, filesystem, escalation, exfiltration, multi-step) |
| AgentDojo coverage | 9 scenarios, 100% exfiltration prevention |

## Known Accepted Limitations

1. **`path_ambiguity_bypass` scenario**: Tests file path traversal (e.g., `../../etc/shadow`). The simulation stub executor does not enforce path constraints — it grants all `file.read` requests. This scenario requires the real `FileExecutor` with `FILE_EXECUTOR_ROOT` path canonicalization. Included to document the expected threat; will pass once executor-level path enforcement is wired into the sim runner.

2. **Stub vs. real executor differences**: Simulation stubs return synthetic data and do not exercise executor-level constraints (path sandboxing, DNS resolution, TLS verification). Policy rules and behavioral patterns are fully exercised.

3. **Single-principal simulation limit**: YAML scenarios test one principal. Cross-principal scenarios validate policy blocking but not the full `SharedTaintRegistry` multi-instance flow. Use the programmatic API with multiple `Firewall` instances for comprehensive cross-principal testing.

4. **PolicyEngine defense-in-depth gap**: The PolicyEngine's pattern matching is weaker than the runtime pipeline's hardened checks (behavioral rules, taint propagation, sticky state). This is documented architecture — the runtime pipeline is the primary enforcement layer; PolicyEngine provides supplementary rule matching.

5. **Sidecar ≠ OS sandbox**: Sidecar mode provides process-level isolation but is not equivalent to OS-level sandboxing. For highest assurance, combine with container isolation (documented in security model).
