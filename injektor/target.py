"""Explicit-target OpenAI-compatible chat completions adapter."""
from __future__ import annotations

import json
import time

import httpx

from .config import TargetConfig

MAX_RESPONSE_BYTES = 1_000_000


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
            # Reject before any HTTP library can echo the value in an exception message.
            if not key.isascii() or not key.isprintable():
                raise TargetError("API key contains characters that are not valid in an HTTP header.")
            headers["Authorization"] = f"Bearer {key}"
        body = {"model": self.config.model, "messages": [{"role": "user", "content": prompt}]}
        for attempt in range(self.config.retries + 1):
            try:
                return self._attempt(headers, body)
            except TargetError:
                raise
            except (httpx.HTTPError, httpx.InvalidURL, ValueError, RecursionError) as exc:
                if attempt >= self.config.retries:
                    # Only the exception type is reported; messages may embed header values.
                    raise TargetError(f"Target request failed ({type(exc).__name__}).") from None
                time.sleep(0.2 * (attempt + 1))
        raise TargetError("Target request failed.")

    def _attempt(self, headers: dict[str, str], body: dict) -> str:
        # httpx timeouts apply per socket operation, so a slow-drip body needs its own deadline.
        deadline = time.monotonic() + self.config.timeout
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
                    if size > MAX_RESPONSE_BYTES:
                        raise TargetError("Target response exceeded the 1 MB limit.")
                    if time.monotonic() > deadline:
                        raise httpx.ReadTimeout("Total response deadline exceeded.")
                    chunks.append(chunk)
        data = json.loads(b"".join(chunks))
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise TargetError("Target response did not contain a chat completion.") from exc
        if not isinstance(content, str):
            raise TargetError("Target response content must be text.")
        return content[:20_000]
