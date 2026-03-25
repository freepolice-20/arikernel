"""
Integration test for the AriKernel Python sidecar client.

Starts the TypeScript sidecar (packages/sidecar), creates a SidecarKernel,
and verifies that allowed and denied tool calls produce the correct decisions.

Requires:
    cd <repo-root>
    pnpm build

Run:
    # Start sidecar first (in another terminal or via CI):
    node -e "import('@arikernel/sidecar').then(m => m.createSidecarServer({devMode:true}).listen())"

    # Then run tests:
    pip install -e python/
    python -m pytest python/tests/test_integration.py -v
"""

import http.server
import os
import subprocess
import sys
import threading
import time

import pytest

# Allow importing from the python package in the repo
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from arikernel.sidecar import SidecarKernel
from arikernel.runtime.kernel import ToolCallDenied, create_kernel

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SIDECAR_PORT = int(os.environ.get("SIDECAR_PORT", "8787"))
SIDECAR_URL = f"http://localhost:{SIDECAR_PORT}"


def _sidecar_is_running() -> bool:
    """Check if the sidecar is already running."""
    try:
        import httpx
        resp = httpx.get(f"{SIDECAR_URL}/health", timeout=2)
        return resp.status_code == 200 and resp.json().get("service") == "arikernel-sidecar"
    except Exception:
        return False


@pytest.fixture(scope="module")
def sidecar():
    """Ensure the TypeScript sidecar is running for the test session.

    If a sidecar is already running on the expected port (e.g., started by CI),
    use it directly. Otherwise, start one as a subprocess.
    """
    if _sidecar_is_running():
        yield None  # external sidecar, don't manage it
        return

    # Start sidecar subprocess
    proc = subprocess.Popen(
        [
            "node", "-e",
            "import('@arikernel/sidecar').then(m => "
            "m.createSidecarServer({devMode:true}).listen().then(() => "
            "console.log('Sidecar listening')))"
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=REPO_ROOT,
    )

    # Wait for sidecar to be ready
    import httpx
    for _ in range(30):
        try:
            resp = httpx.get(f"{SIDECAR_URL}/health", timeout=1)
            if resp.status_code == 200:
                break
        except Exception:
            pass
        time.sleep(0.5)
    else:
        proc.kill()
        raise RuntimeError(
            f"Sidecar did not start on {SIDECAR_URL}. "
            "Run `pnpm build` first, then start the sidecar or set SIDECAR_PORT."
        )

    yield proc

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture(scope="module")
def local_http_server():
    """Start a local HTTP server for integration tests (no external network needed)."""

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

        def log_message(self, *args):
            pass  # silence request logs

    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.fixture
def kernel(sidecar):
    """Create a SidecarKernel connected to the test sidecar."""
    k = SidecarKernel(
        url=SIDECAR_URL,
        principal="test-agent",
    )
    yield k
    k.close()


def test_health(sidecar):
    """Sidecar responds to health check."""
    import httpx
    resp = httpx.get(f"{SIDECAR_URL}/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "arikernel-sidecar"


def test_create_kernel_sidecar_mode(sidecar):
    """create_kernel() in sidecar mode connects to the sidecar."""
    k = create_kernel(
        preset="safe-research",
        mode="sidecar",
        sidecar_url=SIDECAR_URL,
        principal="test-create",
    )
    assert k.preset == "safe-research"
    k.close()


def test_capability_granted(kernel):
    """Requesting a matching capability is granted."""
    grant = kernel.request_capability("http.read")
    assert grant["granted"] is True
    assert grant.get("grant_id") is not None


def test_capability_denied(kernel):
    """Requesting a capability the principal lacks is denied."""
    grant = kernel.request_capability("shell.exec")
    assert grant["granted"] is False


def test_execute_allowed(kernel, local_http_server):
    """Tool call within granted scope is allowed."""
    result = kernel.execute_tool(
        tool_class="http",
        action="get",
        parameters={"url": local_http_server},
    )
    assert result["verdict"] == "allow"
    assert result.get("call_id") is not None


def test_execute_denied(kernel):
    """Tool call outside granted scope is denied."""
    with pytest.raises(ToolCallDenied):
        kernel.execute_tool(
            tool_class="shell",
            action="exec",
            parameters={"command": "echo hello"},
        )


def test_execute_fn_ignored_in_sidecar(kernel, local_http_server):
    """execute_fn is ignored in sidecar mode — sidecar executes tools."""
    sentinel = {"called": False}

    def should_not_run(**kwargs):
        sentinel["called"] = True
        return "local result"

    import warnings
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        result = kernel.execute_tool(
            tool_class="http",
            action="get",
            parameters={"url": local_http_server},
            execute_fn=should_not_run,
        )

    # execute_fn must NOT have been called
    assert sentinel["called"] is False, "execute_fn should not be called in sidecar mode"
    assert result["verdict"] == "allow"
    # Should have emitted a warning about execute_fn being ignored
    exec_fn_warns = [x for x in w if "execute_fn is ignored" in str(x.message)]
    assert len(exec_fn_warns) >= 1


def test_status(kernel, local_http_server):
    """Status endpoint returns principal state."""
    # Make at least one call so the principal exists
    kernel.execute_tool(
        tool_class="http",
        action="get",
        parameters={"url": local_http_server},
    )
    status = kernel.status()
    assert "restricted" in status


def test_denial_returns_403(kernel):
    """Denied calls raise ToolCallDenied with a reason."""
    with pytest.raises(ToolCallDenied) as exc_info:
        kernel.execute_tool(
            tool_class="shell",
            action="exec",
            parameters={"command": "rm -rf /"},
        )
    assert exc_info.value.reason  # has a reason string
    assert exc_info.value.verdict == "deny"


def test_execute_allowed_but_failed(kernel):
    """Allowed tool call that fails operationally returns success=False (not 403).

    This validates the allowed/success decoupling: policy allows the call (HTTP 200,
    verdict=allow) but the executor fails (success=False with error message).
    """
    result = kernel.execute_tool(
        tool_class="file",
        action="read",
        parameters={"path": "/nonexistent/path/that/does/not/exist.txt"},
    )
    assert result["verdict"] == "allow"
    assert result["success"] is False
    assert result.get("error")  # executor should provide an error message
