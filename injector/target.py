"""Explicit-target OpenAI-compatible chat completions adapter."""
from __future__ import annotations

import json
import time

import httpx

from .config import TargetConfig


class TargetError(RuntimeError):
    pass


class OpenAICompatibleTarget:
    def __init__(self, config: TargetConfig, transport: httpx.BaseTransport | None = None):
        self.config = config
        self.transport = transport

    def ask(self, prompt: str) -> str:
        headers = {"Content-Type": "application/json"}
        key = self.config.credential()
        if key:
            headers["Authorization"] = f"Bearer {key}"
        body = {"model": self.config.model, "messages": [{"role": "user", "content": prompt}]}
        for attempt in range(self.config.retries + 1):
            try:
                with httpx.Client(timeout=self.config.timeout, follow_redirects=False, trust_env=False,
                                  transport=self.transport) as client:
                    with client.stream("POST", self.config.endpoint, headers=headers, json=body) as response:
                        if 300 <= response.status_code < 400:
                            raise TargetError("Target returned a redirect; redirects are disabled.")
                        if response.status_code >= 400:
                            raise TargetError(f"Target returned HTTP {response.status_code}.")
                        chunks, size = [], 0
                        for chunk in response.iter_bytes():
                            size += len(chunk)
                            if size > 1_000_000:
                                raise TargetError("Target response exceeded the 1 MB limit.")
                            chunks.append(chunk)
                data = json.loads(b"".join(chunks))
                try:
                    content = data["choices"][0]["message"]["content"]
                except (KeyError, IndexError, TypeError) as exc:
                    raise TargetError("Target response did not contain a chat completion.") from exc
                if not isinstance(content, str):
                    raise TargetError("Target response content must be text.")
                return content[:20_000]
            except TargetError:
                raise
            except (httpx.TimeoutException, httpx.NetworkError, ValueError) as exc:
                if attempt >= self.config.retries:
                    raise TargetError(f"Target request failed ({type(exc).__name__}).") from exc
                time.sleep(0.2 * (attempt + 1))
        raise TargetError("Target request failed.")
