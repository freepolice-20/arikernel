"""
Integration test for the Agent Firewall Python client.

Starts the TypeScript server, creates a session, and verifies
that allowed and denied tool calls produce the correct decisions.

Run:
    cd <repo-root>
    pnpm build
    pip install -e python/
    python -m pytest python/tests/test_integration.py -v
"""

import os
import subprocess
import sys
import time

import pytest

# Allow importing from the python package in the repo
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_firewall import FirewallClient, ToolCallDenied

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SERVER_PORT = 9198  # Use a non-default port to avoid conflicts
POLICY = os.path.join(REPO_ROOT, "policies", "safe-defaults.yaml")
AUDIT_DB = os.path.join(REPO_ROOT, "test-integration-audit.db")


@pytest.fixture(scope="module")
def server():
    """Start the Agent Firewall server for the test session."""
    # Clean up stale audit DB
    if os.path.exists(AUDIT_DB):
        os.remove(AUDIT_DB)

    env = {**os.environ, "PORT": str(SERVER_PORT), "POLICY": POLICY, "AUDIT_DB": AUDIT_DB}
    proc = subprocess.Popen(
        ["node", os.path.join(REPO_ROOT, "apps", "server", "dist", "main.js")],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=REPO_ROOT,
    )

    # Wait for server to be ready
    import httpx

    for _ in range(30):
        try:
            resp = httpx.get(f"http://localhost:{SERVER_PORT}/health", timeout=1)
            if resp.status_code == 200:
                break
        except Exception:
            pass
        time.sleep(0.2)
    else:
        proc.kill()
        raise RuntimeError("Server did not start in time")

    yield proc

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    # Clean up audit DB
    if os.path.exists(AUDIT_DB):
        os.remove(AUDIT_DB)


@pytest.fixture
def client(server):
    """Create a FirewallClient connected to the test server."""
    fw = FirewallClient(
        url=f"http://localhost:{SERVER_PORT}",
        principal="test-agent",
        capabilities=[
            {
                "toolClass": "http",
                "actions": ["get"],
                "constraints": {"allowedHosts": ["api.github.com"]},
            },
        ],
    )
    yield fw
    fw.close()


def test_health(server):
    """Server responds to health check."""
    import httpx

    resp = httpx.get(f"http://localhost:{SERVER_PORT}/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"


def test_session_creation(client):
    """Client creates a session and receives IDs."""
    assert client.session_id is not None
    assert client.run_id is not None


def test_capability_granted(client):
    """Requesting a matching capability is granted."""
    grant = client.request_capability("http.read")
    assert grant.granted is True
    assert grant.grant_id is not None
    assert grant.expires_at is not None


def test_capability_denied(client):
    """Requesting a capability the principal lacks is denied."""
    grant = client.request_capability("shell.exec")
    assert grant.granted is False
    assert grant.grant_id is None


def test_execute_allowed(client):
    """Tool call within granted scope is allowed."""
    grant = client.request_capability("http.read")
    assert grant.granted

    result = client.execute(
        tool_class="http",
        action="get",
        parameters={"url": "https://api.github.com/repos/example"},
        grant_id=grant.grant_id,
    )
    assert result.verdict == "allow"


def test_execute_denied_no_token(client):
    """Tool call without a capability token is denied."""
    with pytest.raises(ToolCallDenied) as exc_info:
        client.execute(
            tool_class="shell",
            action="exec",
            parameters={"command": "echo hello"},
        )
    assert "token required" in exc_info.value.reason.lower() or "denied" in exc_info.value.reason.lower()


def test_execute_denied_constraint_violation(client):
    """Tool call violating grant constraints is denied."""
    grant = client.request_capability("http.read")
    assert grant.granted

    with pytest.raises(ToolCallDenied):
        client.execute(
            tool_class="http",
            action="get",
            parameters={"url": "https://evil.com/steal"},
            grant_id=grant.grant_id,
        )


def test_revoke_grant(client):
    """Revoking a grant prevents further use."""
    grant = client.request_capability("http.read")
    assert grant.granted

    revoked = client.revoke_grant(grant.grant_id)
    assert revoked is True

    with pytest.raises(ToolCallDenied):
        client.execute(
            tool_class="http",
            action="get",
            parameters={"url": "https://api.github.com/repos/example"},
            grant_id=grant.grant_id,
        )
