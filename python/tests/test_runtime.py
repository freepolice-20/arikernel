"""Tests for the AriKernel Python runtime.

Unit tests use mode="local" since the TypeScript sidecar is not available.
Integration tests for the sidecar path are in test_integration.py.
"""

from __future__ import annotations

import os
import sqlite3
import json
import tempfile
import warnings
from pathlib import Path

import pytest

from arikernel.runtime.kernel import create_kernel, Kernel, ToolCallDenied, ApprovalRequiredError
from arikernel.runtime.policy_engine import PolicyEngine
from arikernel.runtime.taint_tracking import TaintLabel, TaintTracker, create_taint_label, merge_labels
from arikernel.runtime.capability_tokens import CapabilityIssuer, TokenStore
from arikernel.runtime.run_state import RunStateTracker
from arikernel.runtime.behavior_rules import evaluate_behavioral_rules, apply_behavioral_rule, _check_tainted_shell_with_data
from arikernel.runtime.hash_chain import compute_hash, verify_chain, GENESIS_HASH
from arikernel.runtime.audit_logger import AuditStore
from arikernel.runtime.autoscope import classify_scope
from arikernel.runtime.spec_loader import get_preset, get_defaults


# ── Hash chain tests ───────────────────────────────────────────────

class TestHashChain:
    def test_genesis_hash_is_64_zeros(self):
        assert GENESIS_HASH == "0" * 64

    def test_compute_hash_deterministic(self):
        h1 = compute_hash("test data", GENESIS_HASH)
        h2 = compute_hash("test data", GENESIS_HASH)
        assert h1 == h2

    def test_compute_hash_different_data(self):
        h1 = compute_hash("data1", GENESIS_HASH)
        h2 = compute_hash("data2", GENESIS_HASH)
        assert h1 != h2

    def test_verify_chain_valid(self):
        h1 = compute_hash("event1", GENESIS_HASH)
        h2 = compute_hash("event2", h1)
        events = [
            {"hash": h1, "previousHash": GENESIS_HASH, "data": "event1"},
            {"hash": h2, "previousHash": h1, "data": "event2"},
        ]
        assert verify_chain(events) == {"valid": True}

    def test_verify_chain_broken(self):
        h1 = compute_hash("event1", GENESIS_HASH)
        events = [
            {"hash": h1, "previousHash": GENESIS_HASH, "data": "event1"},
            {"hash": "badhash", "previousHash": h1, "data": "event2"},
        ]
        result = verify_chain(events)
        assert result["valid"] is False
        assert result["brokenAt"] == 1

    def test_compatible_with_ts_algorithm(self):
        """The hash algorithm must match: sha256(previousHash + data)."""
        import hashlib
        prev = GENESIS_HASH
        data = '{"toolCall":{},"decision":{}}'
        expected = hashlib.sha256(
            prev.encode("utf-8") + data.encode("utf-8")
        ).hexdigest()
        assert compute_hash(data, prev) == expected


# ── Policy engine tests ────────────────────────────────────────────

class TestPolicyEngine:
    def test_deny_all_default(self):
        engine = PolicyEngine()
        decision = engine.evaluate(
            {"toolClass": "http", "action": "get", "parameters": {}},
            [],
            [{"toolClass": "http", "actions": ["get"]}],
        )
        assert decision["verdict"] == "deny"

    def test_allow_http_get(self):
        engine = PolicyEngine([{
            "id": "allow-http-get",
            "name": "Allow HTTP GET",
            "priority": 100,
            "match": {"toolClass": "http", "action": "get"},
            "decision": "allow",
            "reason": "HTTP GET allowed",
        }])
        decision = engine.evaluate(
            {"toolClass": "http", "action": "get", "parameters": {}},
            [],
            [{"toolClass": "http", "actions": ["get"]}],
        )
        assert decision["verdict"] == "allow"

    def test_no_capability_denies(self):
        engine = PolicyEngine()
        decision = engine.evaluate(
            {"toolClass": "shell", "action": "exec", "parameters": {}},
            [],
            [],  # no capabilities
        )
        assert decision["verdict"] == "deny"
        assert "No capability grant" in decision["reason"]

    def test_action_not_in_capability(self):
        engine = PolicyEngine()
        decision = engine.evaluate(
            {"toolClass": "http", "action": "post", "parameters": {}},
            [],
            [{"toolClass": "http", "actions": ["get"]}],
        )
        assert decision["verdict"] == "deny"
        assert "not allowed" in decision["reason"]

    def test_path_constraint_violation(self):
        engine = PolicyEngine([{
            "id": "allow-file-read",
            "name": "Allow file reads",
            "priority": 100,
            "match": {"toolClass": "file", "action": "read"},
            "decision": "allow",
            "reason": "allowed",
        }])
        decision = engine.evaluate(
            {"toolClass": "file", "action": "read", "parameters": {"path": "/etc/shadow"}},
            [],
            [{"toolClass": "file", "actions": ["read"], "constraints": {"allowedPaths": ["./data/**"]}}],
        )
        assert decision["verdict"] == "deny"
        assert "not in allowed paths" in decision["reason"]

    def test_taint_source_matching(self):
        engine = PolicyEngine([{
            "id": "deny-tainted-shell",
            "name": "Block tainted shell",
            "priority": 10,
            "match": {"toolClass": "shell", "taintSources": ["web"]},
            "decision": "deny",
            "reason": "Tainted shell blocked",
        }, {
            "id": "allow-shell",
            "name": "Allow shell",
            "priority": 100,
            "match": {"toolClass": "shell"},
            "decision": "allow",
            "reason": "Shell allowed",
        }])
        # With taint -> deny
        decision = engine.evaluate(
            {"toolClass": "shell", "action": "exec", "parameters": {}},
            [TaintLabel(source="web", origin="test")],
            [{"toolClass": "shell", "actions": ["exec"]}],
        )
        assert decision["verdict"] == "deny"

        # Without taint -> allow
        decision2 = engine.evaluate(
            {"toolClass": "shell", "action": "exec", "parameters": {}},
            [],
            [{"toolClass": "shell", "actions": ["exec"]}],
        )
        assert decision2["verdict"] == "allow"


# ── Taint tracking tests ──────────────────────────────────────────

class TestTaintTracking:
    def test_create_label(self):
        label = create_taint_label("web", "google.com", 0.9)
        assert label.source == "web"
        assert label.origin == "google.com"
        assert label.confidence == 0.9
        assert label.added_at != ""

    def test_confidence_clamped(self):
        label = TaintLabel(source="web", origin="test", confidence=1.5)
        assert label.confidence == 1.0
        label2 = TaintLabel(source="web", origin="test", confidence=-0.5)
        assert label2.confidence == 0.0

    def test_merge_deduplicates(self):
        a = [TaintLabel(source="web", origin="a"), TaintLabel(source="rag", origin="b")]
        b = [TaintLabel(source="web", origin="a")]
        merged = merge_labels(a, b)
        assert len(merged) == 2

    def test_propagate_adds_tool_output(self):
        tracker = TaintTracker()
        inputs = [TaintLabel(source="web", origin="test")]
        output = tracker.propagate(inputs, "call-123")
        sources = [t.source for t in output]
        assert "web" in sources
        assert "tool-output" in sources
        # Propagated label should have propagated_from
        web_label = next(t for t in output if t.source == "web")
        assert web_label.propagated_from == "call-123"

    def test_to_dict_roundtrip(self):
        label = TaintLabel(source="email", origin="inbox", confidence=0.8)
        d = label.to_dict()
        restored = TaintLabel.from_dict(d)
        assert restored.source == "email"
        assert restored.origin == "inbox"
        assert restored.confidence == 0.8


# ── Capability tokens tests ───────────────────────────────────────

class TestCapabilityTokens:
    def test_issue_and_validate(self):
        store = TokenStore()
        counter = [0]
        def gen_id():
            counter[0] += 1
            return f"grant-{counter[0]}"
        issuer = CapabilityIssuer(
            [{"toolClass": "http", "actions": ["get"], "constraints": {"allowedHosts": ["*"]}}],
            store,
            gen_id,
        )
        result = issuer.evaluate("http.read", "principal-1")
        assert result["granted"] is True
        assert store.validate(result["grant_id"])

    def test_deny_no_capability(self):
        store = TokenStore()
        issuer = CapabilityIssuer([], store, lambda: "id")
        result = issuer.evaluate("http.read", "principal-1")
        assert result["granted"] is False

    def test_taint_blocks_sensitive_class(self):
        store = TokenStore()
        issuer = CapabilityIssuer(
            [{"toolClass": "shell", "actions": ["exec"]}],
            store,
            lambda: "id",
        )
        labels = [TaintLabel(source="web", origin="test")]
        result = issuer.evaluate("shell.exec", "principal-1", labels)
        assert result["granted"] is False
        assert "untrusted taint" in result["reason"]

    def test_consume_and_exhaust(self):
        store = TokenStore()
        from arikernel.runtime.capability_tokens import CapabilityGrant
        from datetime import datetime, timezone, timedelta
        grant = CapabilityGrant(
            grant_id="g1",
            principal_id="p1",
            capability_class="http.read",
            tool_class="http",
            actions=["get"],
            constraints=None,
            expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            max_calls=2,
        )
        store.store(grant)
        assert store.consume("g1") is True
        assert store.consume("g1") is True
        assert store.consume("g1") is False  # exhausted

    def test_revoke(self):
        store = TokenStore()
        from arikernel.runtime.capability_tokens import CapabilityGrant
        from datetime import datetime, timezone, timedelta
        grant = CapabilityGrant(
            grant_id="g1",
            principal_id="p1",
            capability_class="http.read",
            tool_class="http",
            actions=["get"],
            constraints=None,
            expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            max_calls=10,
        )
        store.store(grant)
        assert store.validate("g1") is True
        store.revoke("g1")
        assert store.validate("g1") is False


# ── Run state tests ───────────────────────────────────────────────

class TestRunState:
    def test_quarantine_on_threshold(self):
        tracker = RunStateTracker(max_denied_sensitive_actions=3)
        for _ in range(3):
            tracker.record_denied_action()
        assert tracker.restricted is True
        assert tracker.quarantine_info["triggerType"] == "threshold"

    def test_quarantine_by_rule(self):
        tracker = RunStateTracker()
        result = tracker.quarantine_by_rule("test_rule", "test reason", [])
        assert result is not None
        assert tracker.restricted is True
        # Second quarantine returns None
        assert tracker.quarantine_by_rule("rule2", "reason2", []) is None

    def test_restricted_mode_allows_safe_actions(self):
        tracker = RunStateTracker(max_denied_sensitive_actions=1)
        tracker.record_denied_action()
        assert tracker.restricted
        assert tracker.is_allowed_in_restricted_mode("http", "get")
        assert tracker.is_allowed_in_restricted_mode("file", "read")
        assert not tracker.is_allowed_in_restricted_mode("shell", "exec")
        assert not tracker.is_allowed_in_restricted_mode("http", "post")

    def test_sensitive_path_detection(self):
        tracker = RunStateTracker()
        assert tracker.is_sensitive_path("/home/user/.ssh/id_rsa")
        assert tracker.is_sensitive_path("/app/.env")
        assert tracker.is_sensitive_path("config/credentials.json")
        assert not tracker.is_sensitive_path("./data/report.csv")

    def test_egress_action_detection(self):
        tracker = RunStateTracker()
        assert tracker.is_egress_action("post")
        assert tracker.is_egress_action("put")
        assert not tracker.is_egress_action("get")

    def test_event_window_size_limited(self):
        tracker = RunStateTracker()
        for i in range(30):
            tracker.push_event({"timestamp": "", "type": "tool_call_allowed"})
        assert len(tracker.recent_events) == 20


# ── Behavioral rules tests ────────────────────────────────────────

class TestBehavioralRules:
    def test_web_taint_then_shell_quarantines(self):
        tracker = RunStateTracker()
        tracker.push_event({
            "timestamp": "", "type": "taint_observed",
            "taintSources": ["web"],
        })
        tracker.push_event({
            "timestamp": "", "type": "tool_call_allowed",
            "toolClass": "shell", "action": "exec",
        })
        match = evaluate_behavioral_rules(tracker)
        assert match is not None
        assert match["ruleId"] == "web_taint_sensitive_probe"

    def test_denied_then_escalation_quarantines(self):
        tracker = RunStateTracker()
        tracker.push_event({
            "timestamp": "", "type": "capability_denied",
            "toolClass": "http",
        })
        tracker.push_event({
            "timestamp": "", "type": "capability_requested",
            "toolClass": "shell",
        })
        match = evaluate_behavioral_rules(tracker)
        assert match is not None
        assert match["ruleId"] == "denied_capability_then_escalation"

    def test_sensitive_read_then_egress_quarantines(self):
        tracker = RunStateTracker()
        tracker.push_event({
            "timestamp": "", "type": "sensitive_read_attempt",
            "metadata": {"path": "/home/.ssh/id_rsa"},
        })
        tracker.push_event({
            "timestamp": "", "type": "egress_attempt",
            "action": "post",
        })
        match = evaluate_behavioral_rules(tracker)
        assert match is not None
        assert match["ruleId"] == "sensitive_read_then_egress"

    def test_no_match_on_safe_events(self):
        tracker = RunStateTracker()
        tracker.push_event({"timestamp": "", "type": "tool_call_allowed", "toolClass": "http"})
        tracker.push_event({"timestamp": "", "type": "tool_call_allowed", "toolClass": "file"})
        assert evaluate_behavioral_rules(tracker) is None

    def test_tainted_database_write_quarantines(self):
        tracker = RunStateTracker()
        tracker.push_event({
            "timestamp": "", "type": "taint_observed",
            "taintSources": ["web"],
        })
        tracker.push_event({
            "timestamp": "", "type": "tool_call_allowed",
            "toolClass": "database", "action": "insert",
        })
        match = evaluate_behavioral_rules(tracker)
        assert match is not None
        assert match["ruleId"] == "tainted_database_write"

    def test_tainted_shell_with_data_quarantines(self):
        tracker = RunStateTracker()
        tracker.push_event({
            "timestamp": "", "type": "taint_observed",
            "taintSources": ["web"],
        })
        tracker.push_event({
            "timestamp": "", "type": "tool_call_allowed",
            "toolClass": "shell", "action": "exec",
            "metadata": {"commandLength": 150},
        })
        # Test the rule directly since rule 1 catches taint+shell first in the full chain
        match = _check_tainted_shell_with_data(tracker.recent_events)
        assert match is not None
        assert match["ruleId"] == "tainted_shell_with_data"

    def test_tainted_shell_short_command_no_match(self):
        tracker = RunStateTracker()
        tracker.push_event({
            "timestamp": "", "type": "taint_observed",
            "taintSources": ["web"],
        })
        tracker.push_event({
            "timestamp": "", "type": "tool_call_allowed",
            "toolClass": "shell", "action": "exec",
            "metadata": {"commandLength": 50},
        })
        match = _check_tainted_shell_with_data(tracker.recent_events)
        assert match is None

    def test_secret_access_then_any_egress_quarantines(self):
        tracker = RunStateTracker()
        tracker.push_event({
            "timestamp": "", "type": "tool_call_allowed",
            "toolClass": "database", "action": "query",
            "metadata": {"query": "SELECT * FROM secrets WHERE id=1"},
        })
        tracker.push_event({
            "timestamp": "", "type": "egress_attempt",
            "action": "post",
        })
        match = evaluate_behavioral_rules(tracker)
        assert match is not None
        assert match["ruleId"] == "secret_access_then_any_egress"

    def test_secret_access_via_url_then_egress(self):
        tracker = RunStateTracker()
        tracker.push_event({
            "timestamp": "", "type": "tool_call_allowed",
            "toolClass": "http", "action": "get",
            "metadata": {"url": "https://vault.internal/v1/secret"},
        })
        tracker.push_event({
            "timestamp": "", "type": "egress_attempt",
            "action": "post",
        })
        match = evaluate_behavioral_rules(tracker)
        assert match is not None
        assert match["ruleId"] == "secret_access_then_any_egress"

    def test_no_match_when_restricted(self):
        tracker = RunStateTracker()
        tracker.quarantine_by_rule("test", "test", [])
        tracker.push_event({"timestamp": "", "type": "taint_observed", "taintSources": ["web"]})
        tracker.push_event({"timestamp": "", "type": "egress_attempt"})
        assert evaluate_behavioral_rules(tracker) is None


# ── AutoScope tests ───────────────────────────────────────────────

class TestAutoScope:
    def test_web_tasks(self):
        assert classify_scope("search the web for data")["preset"] == "safe-research"
        assert classify_scope("summarize this webpage")["preset"] == "safe-research"

    def test_document_tasks(self):
        assert classify_scope("analyze this CSV file")["preset"] == "rag-reader"
        assert classify_scope("parse PDF document")["preset"] == "rag-reader"

    def test_coding_tasks(self):
        assert classify_scope("refactor the code")["preset"] == "workspace-assistant"
        assert classify_scope("fix bug and run tests")["preset"] == "workspace-assistant"

    def test_automation_tasks(self):
        assert classify_scope("sync records to a CRM")["preset"] == "automation-agent"
        assert classify_scope("automate the workflow")["preset"] == "automation-agent"

    def test_fallback_on_ambiguous(self):
        result = classify_scope("do something random")
        assert result["preset"] == "safe-research"
        assert result["confidence"] == 0.0

    def test_scores_present(self):
        result = classify_scope("search the web")
        assert "safe-research" in result["scores"]
        assert "rag-reader" in result["scores"]


# ── Kernel integration tests ─────────────────────────────────────

class TestKernel:
    def test_create_kernel_zero_config(self):
        kernel = create_kernel(mode="local")
        assert kernel.preset == "default"
        assert kernel.auto_scope is False
        kernel.close()

    def test_create_kernel_with_preset(self):
        kernel = create_kernel(mode="local", preset="safe-research")
        assert kernel.preset == "safe-research"
        kernel.close()

    def test_create_kernel_with_auto_scope(self):
        kernel = create_kernel(mode="local", auto_scope=True)
        assert kernel.auto_scope is True
        result = kernel.select_scope("summarize this webpage")
        assert result["preset"] == "safe-research"
        assert kernel.preset == "safe-research"
        kernel.close()

    def test_http_get_allowed(self):
        kernel = create_kernel(mode="local", preset="safe-research")
        grant = kernel.request_capability("http.read")
        assert grant["granted"] is True
        result = kernel.execute_tool(
            "http", "get", {"url": "https://example.com"},
            grant_id=grant["grant_id"],
        )
        assert result["verdict"] == "allow"
        kernel.close()

    def test_shell_denied(self):
        kernel = create_kernel(mode="local", preset="safe-research")
        grant = kernel.request_capability("shell.exec")
        assert grant["granted"] is False
        with pytest.raises(ToolCallDenied):
            kernel.execute_tool("shell", "exec", {"command": "ls"})
        kernel.close()

    def test_file_write_denied(self):
        kernel = create_kernel(mode="local", preset="safe-research")
        with pytest.raises(ToolCallDenied):
            kernel.execute_tool("file", "write", {"path": "/tmp/test.txt"})
        kernel.close()

    def test_execute_fn_called_on_allow(self):
        kernel = create_kernel(mode="local", preset="safe-research")
        grant = kernel.request_capability("http.read")
        called = []
        result = kernel.execute_tool(
            "http", "get", {"url": "https://example.com"},
            grant_id=grant["grant_id"],
            execute_fn=lambda **kw: (called.append(True), "response")[1],
        )
        assert len(called) == 1
        assert result["result"] == "response"
        kernel.close()

    def test_execute_fn_not_called_on_deny(self):
        kernel = create_kernel(mode="local", preset="safe-research")
        called = []
        with pytest.raises(ToolCallDenied):
            kernel.execute_tool(
                "shell", "exec", {"command": "ls"},
                execute_fn=lambda **kw: called.append(True),
            )
        assert len(called) == 0
        kernel.close()

    def test_context_manager(self):
        with create_kernel(mode="local") as kernel:
            grant = kernel.request_capability("http.read")
            assert grant["granted"]

    def test_restricted_mode_after_quarantine(self):
        kernel = create_kernel(mode="local", preset="safe-research", max_denied_sensitive_actions=2)
        # Generate enough denials to trigger quarantine
        for _ in range(2):
            with pytest.raises(ToolCallDenied):
                kernel.execute_tool("shell", "exec", {"command": "rm -rf /"})
        assert kernel.restricted
        # Safe read-only should still work
        grant = kernel.request_capability("http.read")
        result = kernel.execute_tool(
            "http", "get", {"url": "https://example.com"},
            grant_id=grant["grant_id"],
        )
        assert result["verdict"] == "allow"
        # Write should be denied in restricted mode
        with pytest.raises(ToolCallDenied, match="restricted mode"):
            kernel.execute_tool("http", "post", {"url": "https://evil.com"})
        kernel.close()


# ── Audit logging tests ──────────────────────────────────────────

class TestAuditLogging:
    @pytest.fixture
    def db_path(self, tmp_path):
        return str(tmp_path / "test-audit.db")

    def test_audit_log_written(self, db_path):
        kernel = create_kernel(mode="local", preset="safe-research", audit_log=db_path)
        grant = kernel.request_capability("http.read")
        kernel.execute_tool(
            "http", "get", {"url": "https://example.com"},
            grant_id=grant["grant_id"],
        )
        kernel.close()

        conn = sqlite3.connect(db_path)
        runs = conn.execute("SELECT * FROM runs").fetchall()
        events = conn.execute("SELECT * FROM events").fetchall()
        conn.close()

        assert len(runs) == 1
        assert len(events) >= 1

    def test_hash_chain_valid(self, db_path):
        kernel = create_kernel(mode="local", preset="safe-research", audit_log=db_path)
        grant = kernel.request_capability("http.read")
        kernel.execute_tool("http", "get", {"url": "https://a.com"}, grant_id=grant["grant_id"])
        grant2 = kernel.request_capability("http.read")
        kernel.execute_tool("http", "get", {"url": "https://b.com"}, grant_id=grant2["grant_id"])
        try:
            kernel.execute_tool("shell", "exec", {"command": "ls"})
        except ToolCallDenied:
            pass
        kernel.close()

        # Verify hash chain
        conn = sqlite3.connect(db_path)
        rows = conn.execute(
            "SELECT tool_call_json, decision_json, result_json, previous_hash, hash FROM events ORDER BY rowid"
        ).fetchall()
        conn.close()

        chain = []
        for tc_json, dec_json, res_json, prev_hash, hash_val in rows:
            tc = json.loads(tc_json)
            dec = json.loads(dec_json)
            res = json.loads(res_json) if res_json else None
            if res:
                data = json.dumps({"toolCall": tc, "decision": dec, "result": res}, separators=(",", ":"))
            else:
                data = json.dumps({"toolCall": tc, "decision": dec}, separators=(",", ":"))
            chain.append({"hash": hash_val, "previousHash": prev_hash, "data": data})

        result = verify_chain(chain)
        assert result["valid"] is True

    def test_run_lifecycle(self, db_path):
        kernel = create_kernel(mode="local", preset="safe-research", audit_log=db_path)
        run_id = kernel.run_id
        kernel.close()

        conn = sqlite3.connect(db_path)
        row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        conn.close()

        assert row is not None
        # ended_at should be set
        assert row[3] is not None  # ended_at column


# ── Spec loader tests ────────────────────────────────────────────

class TestSpecLoader:
    def test_load_preset(self):
        preset = get_preset("safe-research")
        assert preset["id"] == "safe-research"
        assert len(preset["capabilities"]) > 0
        assert len(preset["policies"]) > 0

    def test_load_defaults(self):
        defaults = get_defaults()
        assert len(defaults["capabilities"]) > 0
        assert len(defaults["policies"]) > 0

    def test_unknown_preset_raises(self):
        with pytest.raises(ValueError, match="Unknown preset"):
            get_preset("nonexistent")

    def test_all_presets_loadable(self):
        for pid in ["safe-research", "rag-reader", "workspace-assistant", "automation-agent"]:
            preset = get_preset(pid)
            assert preset["id"] == pid


# ── Protect decorator tests ──────────────────────────────────────

class TestProtectDecorator:
    def test_protect_tool_allows(self):
        from arikernel import protect_tool
        kernel = create_kernel(mode="local", preset="safe-research")

        @protect_tool("http.read", kernel=kernel)
        def fetch_url(url: str) -> str:
            return f"response from {url}"

        result = fetch_url(url="https://example.com")
        assert result == "response from https://example.com"
        kernel.close()

    def test_protect_tool_denies(self):
        from arikernel import protect_tool
        kernel = create_kernel(mode="local", preset="safe-research")

        @protect_tool("shell.exec", kernel=kernel)
        def run_command(command: str) -> str:
            return "should not reach here"

        with pytest.raises(ToolCallDenied):
            run_command(command="rm -rf /")
        kernel.close()


# ── Parity / conformance tests (Python ↔ TypeScript alignment) ───

class TestRequireApprovalParity:
    """Verify require-approval semantics match TypeScript runtime.

    TypeScript behavior (pipeline.ts):
    - If no onApprovalRequired handler → warn + deny (fail closed)
    - If handler returns false → deny
    - If handler returns true → allow

    Python must match this exactly.
    """

    def _make_kernel_with_approval_policy(self, on_approval=None):
        """Create a kernel with a require-approval policy for shell."""
        return Kernel(
            capabilities=[
                {"toolClass": "http", "actions": ["get"]},
                {"toolClass": "shell", "actions": ["exec"]},
            ],
            policies=[
                {
                    "id": "allow-http-get",
                    "name": "Allow HTTP GET",
                    "priority": 100,
                    "match": {"toolClass": "http", "action": "get"},
                    "decision": "allow",
                    "reason": "HTTP GET allowed",
                },
                {
                    "id": "approve-shell",
                    "name": "Shell requires approval",
                    "priority": 50,
                    "match": {"toolClass": "shell"},
                    "decision": "require-approval",
                    "reason": "Shell commands require approval",
                },
            ],
            on_approval=on_approval,
        )

    def test_no_handler_denies_by_default(self):
        """TS parity: no onApprovalRequired handler → deny + warning."""
        kernel = self._make_kernel_with_approval_policy(on_approval=None)
        with pytest.raises(ApprovalRequiredError) as exc_info:
            kernel.execute_tool("shell", "exec", {"command": "ls"})
        assert "no approval handler" in str(exc_info.value).lower()
        kernel.close()

    def test_no_handler_emits_warning(self):
        """TS parity: warn when no handler is registered."""
        kernel = self._make_kernel_with_approval_policy(on_approval=None)
        with pytest.warns(UserWarning, match="no on_approval handler"):
            with pytest.raises(ApprovalRequiredError):
                kernel.execute_tool("shell", "exec", {"command": "ls"})
        kernel.close()

    def test_handler_returns_false_denies(self):
        """TS parity: handler returns false → deny."""
        kernel = self._make_kernel_with_approval_policy(
            on_approval=lambda tc, dec: False,
        )
        with pytest.raises(ApprovalRequiredError) as exc_info:
            kernel.execute_tool("shell", "exec", {"command": "ls"})
        assert "denied by handler" in str(exc_info.value).lower()
        kernel.close()

    def test_handler_returns_true_allows(self):
        """TS parity: handler returns true → allow execution."""
        called = []
        kernel = self._make_kernel_with_approval_policy(
            on_approval=lambda tc, dec: (called.append(True), True)[1],
        )
        result = kernel.execute_tool("shell", "exec", {"command": "ls"})
        assert result["verdict"] == "require-approval"
        assert len(called) == 1
        kernel.close()

    def test_tool_not_executed_when_denied(self):
        """TS parity: execute_fn must not be called when approval is denied."""
        executed = []
        kernel = self._make_kernel_with_approval_policy(on_approval=None)
        with pytest.raises(ApprovalRequiredError):
            kernel.execute_tool(
                "shell", "exec", {"command": "ls"},
                execute_fn=lambda **kw: executed.append(True),
            )
        assert len(executed) == 0
        kernel.close()

    def test_approval_required_is_subclass_of_denied(self):
        """ApprovalRequiredError should be catchable as ToolCallDenied."""
        kernel = self._make_kernel_with_approval_policy(on_approval=None)
        with pytest.raises(ToolCallDenied):
            kernel.execute_tool("shell", "exec", {"command": "ls"})
        kernel.close()

    def test_denied_action_counted_on_approval_denial(self):
        """TS parity: denied require-approval increments denied action counter."""
        kernel = self._make_kernel_with_approval_policy(on_approval=None)
        for _ in range(5):
            try:
                kernel.execute_tool("shell", "exec", {"command": "ls"})
            except (ApprovalRequiredError, ToolCallDenied):
                pass
        assert kernel.restricted is True
        kernel.close()


class TestVerdictParity:
    """Verify all verdict paths produce the same behavior as TypeScript."""

    def test_deny_verdict_raises(self):
        kernel = create_kernel(mode="local", preset="safe-research")
        with pytest.raises(ToolCallDenied) as exc_info:
            kernel.execute_tool("shell", "exec", {"command": "ls"})
        assert exc_info.value.verdict == "deny"
        kernel.close()

    def test_allow_verdict_returns(self):
        kernel = create_kernel(mode="local", preset="safe-research")
        grant = kernel.request_capability("http.read")
        result = kernel.execute_tool(
            "http", "get", {"url": "https://example.com"},
            grant_id=grant["grant_id"],
        )
        assert result["verdict"] == "allow"
        kernel.close()

    def test_deny_by_default_when_no_rule_matches(self):
        """TS parity: implicit deny-by-default when no policy rule matches."""
        kernel = Kernel(
            capabilities=[{"toolClass": "http", "actions": ["get"]}],
            policies=[],  # No rules — only builtin deny-all
        )
        with pytest.raises(ToolCallDenied) as exc_info:
            kernel.execute_tool("http", "get", {"url": "https://example.com"})
        assert "deny-by-default" in exc_info.value.reason.lower() or "no matching" in exc_info.value.reason.lower()
        kernel.close()


class TestPackagingIntegrity:
    """Verify the spec file is loadable from the installed package."""

    def test_spec_loads_from_package(self):
        """Spec file must be loadable via importlib.resources (not path walking)."""
        from arikernel.runtime.spec_loader import load_spec
        spec = load_spec()
        assert "presets" in spec
        assert "defaults" in spec
        assert "capabilityClasses" in spec
        assert "policyFragments" in spec
        assert "constants" in spec
        assert "autoScope" in spec
        assert "behavioralRules" in spec

    def test_all_presets_loadable_from_package(self):
        for pid in ["safe-research", "rag-reader", "workspace-assistant", "automation-agent"]:
            preset = get_preset(pid)
            assert preset["id"] == pid
            assert len(preset["capabilities"]) > 0
            assert len(preset["policies"]) > 0


# ── Sidecar architecture tests ───────────────────────────────────

class TestSidecarArchitecture:
    """Verify the sidecar-authoritative architecture is correctly wired."""

    def test_default_mode_is_sidecar(self):
        """create_kernel() must default to sidecar mode, not local."""
        # Without a running sidecar, it should raise ConnectionError
        with pytest.raises(ConnectionError, match="Cannot connect to AriKernel sidecar"):
            create_kernel(mode="sidecar", preset="safe-research")

    def test_sidecar_is_default_when_no_mode_specified(self):
        """create_kernel() without mode= should try sidecar."""
        # Suppress the "local mode" warning and ensure it doesn't use local
        with pytest.raises(ConnectionError, match="sidecar"):
            create_kernel(preset="safe-research")

    def test_local_mode_emits_warning(self):
        """Local mode must emit a warning about dev/testing only."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            kernel = create_kernel(mode="local", preset="safe-research")
            kernel.close()
            local_warnings = [x for x in w if "local enforcement mode" in str(x.message).lower()]
            assert len(local_warnings) >= 1

    def test_invalid_mode_raises(self):
        """Invalid mode= values must raise ValueError."""
        with pytest.raises(ValueError, match="Invalid mode"):
            create_kernel(mode="invalid")

    def test_sidecar_kernel_interface_matches_local(self):
        """SidecarKernel must have the same key methods as Kernel."""
        from arikernel.sidecar import SidecarKernel
        # Check that SidecarKernel has the same core methods
        for method in ["request_capability", "execute_tool", "close", "health"]:
            assert hasattr(SidecarKernel, method), f"SidecarKernel missing {method}"

    def test_sidecar_kernel_is_context_manager(self):
        """SidecarKernel must support `with` statement."""
        from arikernel.sidecar import SidecarKernel
        assert hasattr(SidecarKernel, "__enter__")
        assert hasattr(SidecarKernel, "__exit__")

    def test_sidecar_connection_error_is_clear(self):
        """Connection failures must explain how to start the sidecar."""
        with pytest.raises(ConnectionError) as exc_info:
            create_kernel(preset="safe-research", sidecar_url="http://localhost:19999")
        msg = str(exc_info.value)
        assert "pnpm" in msg.lower() or "sidecar" in msg.lower()

    def test_protect_tool_uses_sidecar_by_default(self):
        """protect_tool's default kernel should attempt sidecar connection."""
        from arikernel.protect import _default_kernel, get_default_kernel
        import arikernel.protect as protect_mod
        # Reset global state
        original = protect_mod._default_kernel
        protect_mod._default_kernel = None
        try:
            with pytest.raises(ConnectionError, match="sidecar"):
                get_default_kernel()
        finally:
            protect_mod._default_kernel = original

    def test_sidecar_timeout_fails_closed(self):
        """Sidecar connection timeout must fail closed, not fall back to local."""
        from arikernel.sidecar import SidecarKernel
        # Use a non-routable IP to trigger timeout behavior
        with pytest.raises((ConnectionError, Exception)):
            SidecarKernel(
                url="http://192.0.2.1:9099",  # TEST-NET, non-routable
                timeout=1.0,
            )

    def test_no_try_except_fallback_in_create_kernel(self):
        """Verify create_kernel does NOT catch ConnectionError to fall back to local.

        This is the critical invariant: sidecar failure must propagate, not degrade.
        """
        # If sidecar mode raises ConnectionError, it must propagate to caller
        raised = False
        try:
            create_kernel(mode="sidecar", preset="safe-research")
        except ConnectionError:
            raised = True
        except Exception:
            # Any other exception is also acceptable — as long as it's not silently local
            raised = True
        assert raised, "create_kernel(mode='sidecar') must raise when sidecar unavailable"

    def test_no_create_kernel_call_without_mode_in_tests(self):
        """All test files must use explicit mode='local' — no accidental sidecar.

        Exceptions: TestSidecarArchitecture tests intentionally call without
        mode= to verify fail-closed behavior.
        """
        import ast
        from pathlib import Path

        test_dir = Path(__file__).parent
        violations = []
        for test_file in test_dir.glob("test_*.py"):
            if test_file.name == "test_integration.py":
                continue  # integration tests are allowed to use sidecar
            source = test_file.read_text()
            tree = ast.parse(source)

            # Find lines inside TestSidecarArchitecture class (exempt)
            exempt_lines: set[int] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and node.name == "TestSidecarArchitecture":
                    for child in ast.walk(node):
                        if hasattr(child, "lineno"):
                            exempt_lines.add(child.lineno)

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if node.lineno in exempt_lines:
                        continue
                    func = node.func
                    is_create_kernel = (
                        (isinstance(func, ast.Name) and func.id == "create_kernel") or
                        (isinstance(func, ast.Attribute) and func.attr == "create_kernel")
                    )
                    if is_create_kernel:
                        has_mode = any(kw.arg == "mode" for kw in node.keywords)
                        if not has_mode:
                            violations.append(
                                f"{test_file.name}:{node.lineno}: "
                                f"create_kernel() without explicit mode="
                            )
        assert not violations, (
            "Found create_kernel() calls without explicit mode= in test files. "
            "All tests must specify mode='local' to avoid accidental sidecar dependency.\n"
            + "\n".join(violations)
        )
