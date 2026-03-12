"""Tests for Microsoft AutoGen integration."""

import pytest
from arikernel import create_kernel
from arikernel.runtime.kernel import ToolCallDenied
from arikernel.integrations.autogen import protect_autogen_tool, AutoGenToolWrapper


@pytest.fixture
def kernel():
    k = create_kernel(mode="local", preset="safe-research", audit_log=":memory:")
    yield k
    k.close()


class TestProtectAutogenTool:
    """Test the @protect_autogen_tool decorator."""

    def test_allowed_tool_call(self, kernel):
        @protect_autogen_tool("file.read", kernel=kernel)
        def read_file(path: str) -> str:
            return f"contents of {path}"

        result = read_file(path="./data/report.csv")
        assert result == "contents of ./data/report.csv"

    def test_denied_sensitive_file(self, kernel):
        @protect_autogen_tool("file.read", kernel=kernel)
        def read_file(path: str) -> str:
            return f"contents of {path}"

        with pytest.raises(ToolCallDenied):
            read_file(path="~/.ssh/id_rsa")

    def test_denied_missing_capability(self, kernel):
        @protect_autogen_tool("shell.exec", kernel=kernel)
        def run_command(cmd: str) -> str:
            return f"ran: {cmd}"

        # safe-research preset doesn't include shell.exec
        with pytest.raises(ToolCallDenied):
            run_command(cmd="whoami")

    def test_allowed_http_read(self, kernel):
        @protect_autogen_tool("http.read", kernel=kernel)
        def fetch_url(url: str) -> str:
            return f"fetched {url}"

        result = fetch_url(url="https://example.com/api")
        assert "fetched" in result

    def test_quarantine_after_repeated_denials(self):
        k = create_kernel(
            mode="local",
            preset="safe-research",
            audit_log=":memory:",
            max_denied_sensitive_actions=2,
        )

        @protect_autogen_tool("file.read", kernel=k)
        def read_file(path: str) -> str:
            return f"contents of {path}"

        # Trigger quarantine
        for path in ["~/.ssh/id_rsa", "~/.aws/credentials", "/etc/shadow"]:
            try:
                read_file(path=path)
            except ToolCallDenied:
                pass

        assert k.restricted is True
        k.close()


class TestAutoGenToolWrapper:
    """Test the AutoGenToolWrapper class."""

    def test_register_and_execute(self, kernel):
        wrapper = AutoGenToolWrapper(kernel)
        wrapper.register("greet", "http.read", lambda name="world": f"hello {name}")

        result = wrapper.execute("greet", name="AutoGen")
        assert result == "hello AutoGen"

    def test_unknown_tool_raises(self, kernel):
        wrapper = AutoGenToolWrapper(kernel)

        with pytest.raises(ValueError, match="Unknown tool"):
            wrapper.execute("nonexistent")

    def test_tool_names(self, kernel):
        wrapper = AutoGenToolWrapper(kernel)
        wrapper.register("tool_a", "http.read", lambda: "a")
        wrapper.register("tool_b", "file.read", lambda: "b")

        assert wrapper.tool_names == ["tool_a", "tool_b"]

    def test_denied_tool_in_wrapper(self, kernel):
        wrapper = AutoGenToolWrapper(kernel)
        wrapper.register("read_secret", "file.read", lambda path="": f"data from {path}")

        with pytest.raises(ToolCallDenied):
            wrapper.execute("read_secret", path="~/.ssh/id_rsa")

    def test_fluent_chaining(self, kernel):
        wrapper = (
            AutoGenToolWrapper(kernel)
            .register("a", "http.read", lambda: "a")
            .register("b", "file.read", lambda: "b")
        )

        assert len(wrapper.tool_names) == 2
