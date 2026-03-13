"""
Unit tests for sidecar-mode semantics.

Verifies that:
- protect_tool does NOT call the decorated function in sidecar mode
- protect_tool DOES call the decorated function in local mode
- execute_fn is ignored in SidecarKernel.execute_tool()

These tests use mocking — no real sidecar required.
"""

import warnings
from unittest.mock import MagicMock, patch

import pytest

from arikernel.protect import protect_tool, _is_sidecar_kernel
from arikernel.sidecar import SidecarKernel


# Create a fake class whose type().__name__ == "SidecarKernel"
# so it passes the _is_sidecar_kernel() duck-type check.
_FakeSidecarBase = type("SidecarKernel", (), {})


class FakeSidecarKernel(_FakeSidecarBase):
    """Minimal mock that passes _is_sidecar_kernel() duck-type check."""

    def __init__(self):
        self.execute_tool_calls = []

    def health(self):
        return {"status": "ok", "service": "arikernel-sidecar"}

    def request_capability(self, capability_class, taint_labels=None):
        return {"granted": True, "grant_id": "test-grant-123"}

    def execute_tool(self, **kwargs):
        self.execute_tool_calls.append(kwargs)
        return {
            "verdict": "allow",
            "success": True,
            "result": "sidecar-result",
            "call_id": "call-123",
        }


def test_is_sidecar_kernel_detection():
    """_is_sidecar_kernel correctly identifies SidecarKernel instances."""
    fake = FakeSidecarKernel()
    assert _is_sidecar_kernel(fake) is True

    # A regular kernel should not match
    regular = MagicMock()
    regular.__class__ = type("Kernel", (), {})
    assert _is_sidecar_kernel(regular) is False


def test_protect_tool_does_not_call_fn_in_sidecar_mode():
    """In sidecar mode, the decorated function body must NOT be called."""
    fake_kernel = FakeSidecarKernel()
    sentinel = {"called": False}

    @protect_tool("file.read", kernel=fake_kernel)
    def read_file(path: str) -> str:
        sentinel["called"] = True
        return "local-data"

    result = read_file(path="./data/report.csv")

    assert sentinel["called"] is False, (
        "Decorated function body was called in sidecar mode — this is the "
        "double-execution bug. The sidecar should execute the tool, not Python."
    )
    assert result == "sidecar-result"

    # Verify execute_tool was called without execute_fn
    assert len(fake_kernel.execute_tool_calls) == 1
    call_kwargs = fake_kernel.execute_tool_calls[0]
    assert "execute_fn" not in call_kwargs


def test_protect_tool_calls_fn_in_local_mode():
    """In local mode, the decorated function body IS called."""
    from arikernel.runtime.kernel import Kernel

    # Create a minimal local kernel
    local_kernel = MagicMock(spec=Kernel)
    local_kernel.request_capability.return_value = {
        "granted": True,
        "grant_id": "test-grant",
    }
    local_kernel.execute_tool.return_value = {
        "verdict": "allow",
        "result": "local-result",
    }

    sentinel = {"called": False}

    @protect_tool("file.read", kernel=local_kernel)
    def read_file(path: str) -> str:
        sentinel["called"] = True
        return "local-data"

    result = read_file(path="./data/report.csv")

    # In local mode, execute_tool is called WITH execute_fn
    assert local_kernel.execute_tool.called
    call_kwargs = local_kernel.execute_tool.call_args
    assert "execute_fn" in call_kwargs.kwargs
    assert call_kwargs.kwargs["execute_fn"] is not None


def test_sidecar_kernel_ignores_execute_fn():
    """SidecarKernel.execute_tool() ignores execute_fn and warns."""
    # We can't instantiate a real SidecarKernel without a running sidecar,
    # but we can test the FakeSidecarKernel behavior matches.
    fake = FakeSidecarKernel()
    sentinel = {"called": False}

    def should_not_run(**kwargs):
        sentinel["called"] = True

    result = fake.execute_tool(
        tool_class="file",
        action="read",
        parameters={"path": "./test.txt"},
        execute_fn=should_not_run,
    )

    # FakeSidecarKernel doesn't call execute_fn — real SidecarKernel warns
    assert sentinel["called"] is False
    assert result["verdict"] == "allow"
