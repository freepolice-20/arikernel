"""AriKernel framework integrations.

Provides thin wrappers for popular AI agent frameworks:
- AutoGen: protect_autogen_tool() decorator
- AutoGPT: protect_autogpt_command() decorator
"""

from .autogen import protect_autogen_tool, AutoGenToolWrapper
from .autogpt import protect_autogpt_command, AutoGPTCommandWrapper

__all__ = [
    "protect_autogen_tool",
    "AutoGenToolWrapper",
    "protect_autogpt_command",
    "AutoGPTCommandWrapper",
]
