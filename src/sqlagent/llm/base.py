"""The only thing the agent knows about an LLM: this interface.

Swapping Ollama for a hosted model later means writing one more class that
implements `chat`, then changing a config value. The agent code does not change.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

Message = dict[str, str]   # {"role": "system" | "user" | "assistant", "content": "..."}


@dataclass
class LLMResponse:
    text: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    model: str = ""
    latency_ms: int = 0


class LLMError(RuntimeError):
    """The model could not be reached or returned an error. The message is user-readable."""


class LLMProvider(Protocol):
    name: str

    def chat(self, messages: list[Message], *, max_tokens: int = 512,
             temperature: float = 0.0) -> LLMResponse: ...
