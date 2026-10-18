"""Ollama provider (local models), via its HTTP API."""
from __future__ import annotations

import time

import httpx

from .base import LLMError, LLMResponse, Message


class OllamaProvider:
    name = "ollama"

    def __init__(self, base_url: str, model: str, *, timeout: float = 180.0, num_ctx: int = 8192):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        # Ollama's default context window is small and silently truncates long prompts.
        # The schema description alone is ~2-3k tokens, so ask for more explicitly.
        self.num_ctx = num_ctx

    def chat(self, messages: list[Message], *, max_tokens: int = 512,
             temperature: float = 0.0) -> LLMResponse:
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature, "num_ctx": self.num_ctx,
                        "num_predict": max_tokens},
        }
        t0 = time.perf_counter()
        try:
            r = httpx.post(f"{self.base_url}/api/chat", json=payload, timeout=self.timeout)
        except httpx.ConnectError as e:
            raise LLMError(f"Cannot reach Ollama at {self.base_url}. "
                           f"Is it running? Start it with: ollama serve") from e
        except httpx.TimeoutException as e:
            raise LLMError(f"Ollama did not answer within {self.timeout:.0f}s "
                           f"(first request after start loads the model and can be slow).") from e
        if r.status_code == 404:
            raise LLMError(f"Ollama has no model named '{self.model}'. "
                           f"Run: ollama pull {self.model}")
        if r.status_code >= 400:
            raise LLMError(f"Ollama returned HTTP {r.status_code}: {r.text[:200]}")
        data = r.json()
        return LLMResponse(
            text=data["message"]["content"],
            prompt_tokens=int(data.get("prompt_eval_count") or 0),
            completion_tokens=int(data.get("eval_count") or 0),
            model=self.model,
            latency_ms=int((time.perf_counter() - t0) * 1000),
        )

    def check(self) -> tuple[bool, str]:
        """Is the server up, and is the model pulled?"""
        try:
            r = httpx.get(f"{self.base_url}/api/tags", timeout=5.0)
            r.raise_for_status()
        except httpx.HTTPError as e:
            return False, f"cannot reach Ollama at {self.base_url} ({type(e).__name__}). Run: ollama serve"
        names = [m.get("name", "") for m in r.json().get("models", [])]
        if not any(n == self.model or n.split(":")[0] == self.model for n in names):
            return False, f"model '{self.model}' not installed (have: {', '.join(names) or 'none'}). " \
                          f"Run: ollama pull {self.model}"
        return True, f"Ollama is up and '{self.model}' is installed"
