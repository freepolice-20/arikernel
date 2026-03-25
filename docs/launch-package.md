# Ari Kernel — Launch Package

Everything needed to announce the project publicly.

---

## 1. One-Line GitHub Description

> Runtime security enforcement for AI agents. Capability tokens, taint tracking, behavioral quarantine, and SHA-256 hash-chained audit — before any tool call executes.

(155 characters)

---

## 2. Short Announcement Post

> Releasing Ari Kernel v0.1.0 — runtime security enforcement for AI agents (TypeScript / Node.js). Every tool call passes through an enforcement boundary: capability tokens, taint tracking, behavioral sequence detection, and run-level quarantine. Tamper-evident audit trail.

(250 characters)

---

## 3. Launch Thread (4 Posts)

### Post 1: The Problem

AI agents are getting direct access to tools — HTTP requests, shell commands, file I/O, databases. Most deployments rely on prompt-level instructions or static allow/deny lists. Neither is sufficient.

Prompt filters see text, not typed actions. They have no concept of where data came from. And the LLM can ignore them — there is no enforcement boundary.

Static gateways make binary per-call decisions with no behavioral memory. They cannot detect that "fetch a webpage, then read SSH keys, then POST to an external server" is a prompt injection attack — because they evaluate each call independently.

AI agents should never execute with ambient authority.

### Post 2: What Ari Kernel Does

Ari Kernel is an enforcement layer that sits between the agent and its tools, drawing on the reference monitor concept from OS security. Five enforcement layers:

1. **Short-lived capability tokens** — scoped, time-limited (5 min), usage-limited (10 calls). No ambient authority.
2. **Provenance-aware enforcement** — data carries taint labels (web, rag, email). Untrusted provenance blocks sensitive operations at the issuance layer.
3. **Behavioral sequence detection** — a recent-event window tracks multi-step patterns. Six built-in rules detect prompt-injection-to-exfiltration sequences, privilege escalation, tainted database writes, and credential theft.
4. **Run-level behavioral quarantine** — when a rule matches, the run enters restricted mode. Only read-only actions pass for the rest of the session.
5. **Tamper-evident audit evidence** — SHA-256 hash-chained event store. Quarantine events are first-class audit records.

TypeScript / Node.js. Library-first. Available to use — see LICENSE.md for terms. (Python runtime is experimental and deferred from v0.1.0.)

### Post 3: The Demo

```
pnpm demo:behavioral
```

An agent fetches a webpage (allowed, tagged with `web` taint). Then it tries to read `~/.ssh/id_rsa`. The behavioral rule fires: web taint was followed by sensitive file access. Run quarantined after just 2 events — the threshold of 10 was never reached.

The exfiltration POST? Blocked. The agent cannot even get a capability token.

Then replay the audit trail:

```
pnpm ari replay --latest --verbose --db ./demo-audit.db
```

Every event, every decision, every quarantine trigger — cryptographically chained and verified.

### Post 4: What Ships Today

Ari Kernel ships with sidecar mode for mandatory process-isolated enforcement, a centralized control plane with Ed25519-signed decision receipts, request replay protection, and persistent SQLite audit logs. Auto-taint covers HTTP, RAG, and MCP paths; other sources require manual labeling. The control plane supports multi-sidecar deployments with global taint correlation across agents. A benchmark suite validates 18 attack scenarios are blocked, and `arikernel compliance-report` generates evidence reports for security review.

The core thesis: AI agents should never execute with ambient authority. Every tool call must pass through an enforcement boundary that validates capability tokens, checks data provenance, evaluates behavioral patterns, and logs a tamper-evident decision — before anything executes.

---

## 4. Demo Bullets

**Behavioral quarantine in 2 events.** An agent fetches a webpage with a prompt injection, then tries to read `~/.ssh/id_rsa`. The behavioral rule `web_taint_sensitive_probe` quarantines the run immediately. The exfiltration POST never executes.

**Per-call capability enforcement.** Tokens are scoped, time-limited (5 min), and usage-limited (10 calls). Path constraints, host allowlists, and taint-aware issuance deny actions before the agent even gets a token. No ambient authority.

**Replayable tamper-evident audit trail.** `pnpm ari replay --latest --verbose` renders every decision: ALLOW, QUARANTINE (with trigger rule, reason, and matched pattern), DENY. The SHA-256 hash chain is verified on every replay. Forensic-grade evidence, not just logging.

---

## 5. Replay Snippet

Reusable in blog posts, social posts, and documentation:

```
  #0 ALLOW http.get   [token:01KK3G3W...]
     Taint: web:httpbin.org/html

  #2 QUARANTINE  Run entered restricted mode
     Trigger: behavioral_rule (web_taint_sensitive_probe)
     Reason:  Untrusted web input was followed by file.read attempt
     Pattern: taint_observed(http) → sensitive_read_attempt(file)

  #3 DENY  file.read   ~/.ssh/id_rsa
  #4 DENY  http.post   blocked by quarantine

  Hash chain: VALID
```

---

## 6. Recommended Demo Commands

```bash
# Install and build
pnpm install
pnpm build

# Behavioral quarantine demo — web taint triggers quarantine in 2 events
pnpm demo:behavioral

# Replay the audit trail — shows QUARANTINE, trigger, pattern, hash chain
pnpm ari replay --latest --verbose --db ./demo-audit.db

# LangChain integration — wrapped tools with kernel enforcement
pnpm demo:langchain

# Threshold-based quarantine — repeated denials trigger restricted mode
pnpm demo:run-state

# Prompt injection attack — 4-stage attack blocked by 4 defense layers
pnpm demo:attack

# All tests
pnpm test
```

---

## 7. FAQ / Likely Objections

**Is this a real security boundary?**

In embedded mode, yes — for the threat model it targets. The LLM cannot modify the kernel's policy, tokens, or audit log. Tool calls pass through a typed enforcement pipeline that the LLM has no mechanism to bypass. The kernel is not a prompt; it is code that runs after the LLM decides to call a tool and before the tool executes. See [Architecture § Deployment Modes](../ARCHITECTURE.md) for the full trust boundary analysis.

**Can the agent bypass the kernel in embedded mode?**

The LLM cannot. It can only call functions the framework exposes, and those functions route through the kernel. However, if the agent *framework code* is modified to bypass the kernel (e.g., calling tools directly), enforcement is lost. This is cooperative enforcement. For mandatory enforcement with process isolation, use sidecar mode.

**Why not rely on prompt instructions or system prompts?**

System prompts are advisory text processed by the same model that processes adversarial input. They can be overridden by prompt injection, context overflow, or ambiguous instructions. A system prompt has no enforcement mechanism — it cannot prevent a tool call from executing. It can only suggest the model should not make the call.

**Why not static allowlists?**

Static allowlists evaluate each call independently. They cannot detect that a sequence of individually-legitimate calls (fetch webpage → read SSH keys → POST to attacker) constitutes an attack. They have no concept of data provenance — they don't know the POST payload came from SSH keys fetched after a tainted web request. Ari Kernel adds behavioral sequence detection, taint tracking, and session-level quarantine on top of per-call enforcement.

**What does proxy/sidecar mode change?**

In proxy mode, the kernel runs as a separate process. Tools are only accessible through the proxy — the agent has no direct network path or filesystem access to tools. This provides mandatory mediation (no bypass path within the process boundary), process isolation (agent cannot modify kernel state), and tamper-evident audit isolated from the agent process. It also supports any language, not just TypeScript.

---

## 8. Launch Checklist

- [ ] Push latest commit to `main`
- [ ] Verify `pnpm install && pnpm build` succeeds on clean clone
- [ ] Verify `pnpm demo:behavioral` runs and produces audit output
- [ ] Verify `pnpm ari replay --latest --verbose --db ./demo-audit.db` shows QUARANTINE + VALID hash chain
- [ ] Verify `pnpm demo:langchain` runs successfully
- [ ] Verify `pnpm test` passes all tests
- [ ] Confirm GitHub repo description matches section 1
- [ ] Confirm GitHub topics: `ai-security`, `ai-agents`, `llm-agents`, `runtime-security`, `sandbox`, `capability-security`
- [ ] Post to Hacker News (use short announcement from section 2)
- [ ] Publish launch thread (section 3)
- [ ] Monitor GitHub issues for first 48 hours
- [ ] Respond to first issues/discussions within 24 hours
