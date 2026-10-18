"""A scripted LLM for tests and CI: returns canned replies in order, costs no tokens."""
from __future__ import annotations

from .base import LLMResponse, Message


class FakeProvider:
    name = "fake"

    def __init__(self, responses: list[str]):
        self._responses = list(responses)
        self.calls: list[list[Message]] = []

    def chat(self, messages: list[Message], *, max_tokens: int = 512,
             temperature: float = 0.0) -> LLMResponse:
        self.calls.append(messages)
        if not self._responses:
            raise AssertionError("FakeProvider ran out of scripted responses")
        text = self._responses.pop(0)
        prompt_tokens = sum(len(m["content"]) for m in messages) // 4
        return LLMResponse(text=text, prompt_tokens=prompt_tokens,
                           completion_tokens=len(text) // 4, model="fake", latency_ms=1)
