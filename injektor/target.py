"""Explicit-target OpenAI-compatible chat completions adapter."""
from __future__ import annotations

import asyncio
import contextlib
import json
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import httpx

from .config import TargetConfig

MAX_RESPONSE_BYTES = 1_000_000
MAX_CONTENT_CHARS = 20_000
# Statuses that usually clear on their own. Every other 4xx/5xx is reported immediately:
# repeating a rejected credential or a malformed request only adds load on the target.
RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504})
# The target refused the caller. Sending the credential again cannot help and can lock an
# account, so the scan loop stops contacting the target after the first of these.
AUTH_STATUSES = frozenset({401, 403})
# The longest wait a 429 response may ask for through Retry-After. A longer request is not
# honoured and not retried, so a target cannot hold a scan for as long as it likes.
MAX_RETRY_AFTER_SECONDS = 30.0
# Closing a connection that ran into the request deadline is normally immediate. It may not
# extend the deadline by more than this.
CANCEL_GRACE_SECONDS = 1.0
_STATUS_HINTS = {
    401: "check the API key",
    403: "the credential is not permitted to use this endpoint or model",
    404: "check the endpoint path and model name",
    429: "the target is rate limiting; set INJEKTOR_DELAY to slow the scan down",
}


class TargetError(RuntimeError):
    pass


class AuthenticationRejected(TargetError):
    """The target answered 401 or 403."""


class _RetryableStatus(Exception):
    def __init__(self, status: int, retry_after: float | None = None):
        super().__init__(status)
        self.status = status
        self.retry_after = retry_after


class _DeadlineExceeded(Exception):
    pass


def _status_message(status: int) -> str:
    hint = _STATUS_HINTS.get(status)
    return f"Target returned HTTP {status}" + (f" ({hint})." if hint else ".")


def _retry_after(value: str | None) -> float | None:
    """Seconds a Retry-After header asks for; None when it is absent or not valid."""
    value = (value or "").strip()
    if value.isascii() and value.isdigit():
        return float(value)
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())


class OpenAICompatibleTarget:
    """Sends one prompt at a time. Not usable from inside a running asyncio event loop."""

    def __init__(self, config: TargetConfig, transport: httpx.AsyncBaseTransport | None = None):
        self.config = config
        self.transport = transport
        # True when the most recent answer was cut to MAX_CONTENT_CHARS before detection.
        self.last_response_truncated = False
        self._loop: asyncio.AbstractEventLoop | None = None

    def close(self) -> None:
        """Release the event loop. Safe to call more than once. It does not wait for a host name
        lookup still running on the loop's helper thread (see the README, "Request behavior")."""
        loop, self._loop = self._loop, None
        if loop is None or loop.is_closed():
            return
        with contextlib.suppress(BaseException):
            leftovers = [task for task in asyncio.all_tasks(loop) if not task.done()]
            for task in leftovers:
                task.cancel()
            if leftovers:
                loop.run_until_complete(asyncio.wait(leftovers, timeout=CANCEL_GRACE_SECONDS))
            loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()

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
            pause = 0.2 * (attempt + 1)
            try:
                return self._parse(self._run(self._bounded(headers, body)))
            except TargetError:
                raise
            except _RetryableStatus as exc:
                if attempt >= self.config.retries:
                    raise TargetError(_status_message(exc.status)) from None
                if exc.retry_after is not None:
                    if exc.retry_after > MAX_RETRY_AFTER_SECONDS:
                        raise TargetError(
                            f"Target returned HTTP {exc.status} and asked for a wait longer than "
                            f"{MAX_RETRY_AFTER_SECONDS:g} seconds (Retry-After); not retried."
                        ) from None
                    pause = max(pause, exc.retry_after)
            except _DeadlineExceeded:
                if attempt >= self.config.retries:
                    raise TargetError(f"Target did not answer within the {self.config.timeout:g}-"
                                      "second request deadline.") from None
            except (httpx.HTTPError, httpx.InvalidURL, ValueError, RecursionError) as exc:
                if attempt >= self.config.retries:
                    # Only the exception type is reported; messages may embed header values.
                    raise TargetError(f"Target request failed ({type(exc).__name__}).") from None
            time.sleep(pause)
        raise TargetError("Target request failed.")

    def _run(self, coroutine):
        if self._loop is None:
            self._loop = asyncio.new_event_loop()
        task = self._loop.create_task(coroutine)
        try:
            return self._loop.run_until_complete(task)
        except BaseException:
            # An interrupt leaves the request half-way; close its connection before leaving.
            if not task.done():
                task.cancel()
                with contextlib.suppress(BaseException):
                    self._loop.run_until_complete(task)
            elif not task.cancelled():
                task.exception()  # retrieved, so asyncio does not log it as unhandled
            raise

    async def _bounded(self, headers: dict[str, str], body: dict) -> bytes:
        """One attempt under a wall-clock deadline that covers connecting, the response headers
        and the response body. httpx timeouts apply to single socket operations only, so a
        target that sends one byte at a time would otherwise never time out."""
        attempt = asyncio.ensure_future(self._attempt(headers, body))
        try:
            done, _pending = await asyncio.wait({attempt}, timeout=self.config.timeout)
        except BaseException:
            # Cancelled from outside (an interrupt): do not leave the request running.
            attempt.cancel()
            await asyncio.wait({attempt}, timeout=CANCEL_GRACE_SECONDS)
            if attempt.done() and not attempt.cancelled():
                attempt.exception()
            raise
        if done:
            return attempt.result()
        attempt.cancel()
        # asyncio.wait returns at its timeout whether or not the attempt has finished closing
        # its connection, so a peer that stalls the close cannot extend the deadline further.
        await asyncio.wait({attempt}, timeout=CANCEL_GRACE_SECONDS)
        if attempt.done() and not attempt.cancelled():
            attempt.exception()  # retrieved so that asyncio does not log it as unhandled
        raise _DeadlineExceeded()

    async def _attempt(self, headers: dict[str, str], body: dict) -> bytes:
        async with httpx.AsyncClient(timeout=self.config.timeout, follow_redirects=False,
                                     trust_env=False, transport=self.transport) as client:
            async with client.stream("POST", self.config.endpoint, headers=headers,
                                     json=body) as response:
                status = response.status_code
                if 300 <= status < 400:
                    raise TargetError("Target returned a redirect; redirects are disabled.")
                if status in AUTH_STATUSES:
                    raise AuthenticationRejected(_status_message(status))
                if status in RETRYABLE_STATUSES:
                    raise _RetryableStatus(status, _retry_after(
                        response.headers.get("Retry-After")) if status == 429 else None)
                # Error bodies are never read: they can echo the request, including the key.
                if status >= 400:
                    raise TargetError(_status_message(status))
                chunks, size = [], 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        raise TargetError("Target response exceeded the 1 MB limit.")
                    chunks.append(chunk)
        return b"".join(chunks)

    def _parse(self, payload: bytes) -> str:
        try:
            data = json.loads(payload)
        except (ValueError, RecursionError):
            # A body that is not JSON will not become JSON on a second request.
            raise TargetError("Target response was not valid JSON; is the endpoint an "
                              "OpenAI-compatible chat completions URL?") from None
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise TargetError("Target response did not contain a chat completion.") from exc
        if isinstance(content, list):
            content = _join_text_parts(content)
        if not isinstance(content, str):
            raise TargetError("Target response content must be text.")
        self.last_response_truncated = len(content) > MAX_CONTENT_CHARS
        return content[:MAX_CONTENT_CHARS]


def _join_text_parts(parts: list) -> str | None:
    """Join the text of a content-parts array; None when it holds no text part at all."""
    texts = [part["text"] for part in parts
             if isinstance(part, dict) and part.get("type") == "text"
             and isinstance(part.get("text"), str)]
    return "\n".join(texts) if texts else None
