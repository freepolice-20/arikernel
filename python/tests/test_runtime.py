"""Tests for the native AriKernel Python runtime."""

from __future__ import annotations

import os
import sqlite3
import json
import tempfile
from pathlib import Path

import pytest

from arikernel.runtime.kernel import create_kernel, Kernel, ToolCallDenied
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
        kernel = create_kernel()
        assert kernel.preset == "default"
        assert kernel.auto_scope is False
        kernel.close()

    def test_create_kernel_with_preset(self):
        kernel = create_kernel(preset="safe-research")
        assert kernel.preset == "safe-research"
        kernel.close()

    def test_create_kernel_with_auto_scope(self):
        kernel = create_kernel(auto_scope=True)
        assert kernel.auto_scope is True
        result = kernel.select_scope("summarize this webpage")
        assert result["preset"] == "safe-research"
        assert kernel.preset == "safe-research"
        kernel.close()

    def test_http_get_allowed(self):
        kernel = create_kernel(preset="safe-research")
        grant = kernel.request_capability("http.read")
        assert grant["granted"] is True
        result = kernel.execute_tool(
            "http", "get", {"url": "https://example.com"},
            grant_id=grant["grant_id"],
        )
        assert result["verdict"] == "allow"
        kernel.close()

    def test_shell_denied(self):
        kernel = create_kernel(preset="safe-research")
        grant = kernel.request_capability("shell.exec")
        assert grant["granted"] is False
        with pytest.raises(ToolCallDenied):
            kernel.execute_tool("shell", "exec", {"command": "ls"})
        kernel.close()

    def test_file_write_denied(self):
        kernel = create_kernel(preset="safe-research")
        with pytest.raises(ToolCallDenied):
            kernel.execute_tool("file", "write", {"path": "/tmp/test.txt"})
        kernel.close()

    def test_execute_fn_called_on_allow(self):
        kernel = create_kernel(preset="safe-research")
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
        kernel = create_kernel(preset="safe-research")
        called = []
        with pytest.raises(ToolCallDenied):
            kernel.execute_tool(
                "shell", "exec", {"command": "ls"},
                execute_fn=lambda **kw: called.append(True),
            )
        assert len(called) == 0
        kernel.close()

    def test_context_manager(self):
        with create_kernel() as kernel:
            grant = kernel.request_capability("http.read")
            assert grant["granted"]

    def test_restricted_mode_after_quarantine(self):
        kernel = create_kernel(preset="safe-research", max_denied_sensitive_actions=2)
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
        kernel = create_kernel(preset="safe-research", audit_log=db_path)
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
        kernel = create_kernel(preset="safe-research", audit_log=db_path)
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
        kernel = create_kernel(preset="safe-research", audit_log=db_path)
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
        kernel = create_kernel(preset="safe-research")

        @protect_tool("http.read", kernel=kernel)
        def fetch_url(url: str) -> str:
            return f"response from {url}"

        result = fetch_url(url="https://example.com")
        assert result == "response from https://example.com"
        kernel.close()

    def test_protect_tool_denies(self):
        from arikernel import protect_tool
        kernel = create_kernel(preset="safe-research")

        @protect_tool("shell.exec", kernel=kernel)
        def run_command(command: str) -> str:
            return "should not reach here"

        with pytest.raises(ToolCallDenied):
            run_command(command="rm -rf /")
        kernel.close()
