"""Tests for AutoGPT compatibility layer."""

import pytest
from arikernel import create_kernel
from arikernel.runtime.kernel import ToolCallDenied
from arikernel.integrations.autogpt import protect_autogpt_command, AutoGPTCommandWrapper


@pytest.fixture
def kernel():
    k = create_kernel(preset="safe-research", audit_log=":memory:")
    yield k
    k.close()


class TestProtectAutogptCommand:
    """Test the @protect_autogpt_command decorator."""

    def test_allowed_command(self, kernel):
        @protect_autogpt_command("file.read", kernel=kernel)
        def read_file(path: str) -> str:
            return f"contents of {path}"

        result = read_file(path="./data/report.csv")
        assert result == "contents of ./data/report.csv"

    def test_denied_sensitive_command(self, kernel):
        @protect_autogpt_command("file.read", kernel=kernel)
        def read_file(path: str) -> str:
            return f"contents of {path}"

        with pytest.raises(ToolCallDenied):
            read_file(path="~/.ssh/id_rsa")

    def test_denied_no_capability(self, kernel):
        @protect_autogpt_command("shell.exec", kernel=kernel)
        def execute_shell(command: str) -> str:
            return f"ran: {command}"

        with pytest.raises(ToolCallDenied):
            execute_shell(command="rm -rf /")

    def test_preserves_command_metadata(self, kernel):
        @protect_autogpt_command("http.read", kernel=kernel)
        def browse_web(url: str) -> str:
            """Browse a webpage."""
            return f"content of {url}"

        assert browse_web.command_name == "browse_web"
        assert "Browse" in browse_web.command_description

    def test_quarantine_on_repeated_denials(self):
        k = create_kernel(
            preset="safe-research",
            audit_log=":memory:",
            max_denied_sensitive_actions=2,
        )

        @protect_autogpt_command("file.read", kernel=k)
        def read_file(filename: str) -> str:
            return f"contents of {filename}"

        for p in ["~/.ssh/id_rsa", "~/.aws/credentials", "/etc/shadow"]:
            try:
                read_file(path=p)
            except ToolCallDenied:
                pass

        assert k.restricted is True
        k.close()


class TestAutoGPTCommandWrapper:
    """Test the AutoGPTCommandWrapper class."""

    def test_register_and_execute(self, kernel):
        wrapper = AutoGPTCommandWrapper(kernel)
        wrapper.register("read_file", "file.read", lambda path="": f"read {path}")

        result = wrapper.execute("read_file", path="./data/test.txt")
        assert result == "read ./data/test.txt"

    def test_unknown_command_raises(self, kernel):
        wrapper = AutoGPTCommandWrapper(kernel)

        with pytest.raises(ValueError, match="Unknown command"):
            wrapper.execute("nonexistent")

    def test_command_names(self, kernel):
        wrapper = AutoGPTCommandWrapper(kernel)
        wrapper.register("cmd_a", "http.read", lambda: "a")
        wrapper.register("cmd_b", "file.read", lambda: "b")

        assert wrapper.command_names == ["cmd_a", "cmd_b"]

    def test_command_info(self, kernel):
        wrapper = AutoGPTCommandWrapper(kernel)
        wrapper.register(
            "browse", "http.read", lambda url="": url,
            description="Browse a URL"
        )

        info = wrapper.get_command_info()
        assert len(info) == 1
        assert info[0]["name"] == "browse"
        assert info[0]["description"] == "Browse a URL"
        assert info[0]["capability"] == "http.read"

    def test_denied_command_in_wrapper(self, kernel):
        wrapper = AutoGPTCommandWrapper(kernel)
        wrapper.register("steal_key", "file.read", lambda path="": f"data: {path}")

        with pytest.raises(ToolCallDenied):
            wrapper.execute("steal_key", path="~/.ssh/id_rsa")

    def test_fluent_chaining(self, kernel):
        wrapper = (
            AutoGPTCommandWrapper(kernel)
            .register("a", "http.read", lambda: "a", description="Tool A")
            .register("b", "file.read", lambda: "b", description="Tool B")
        )

        assert len(wrapper.command_names) == 2
