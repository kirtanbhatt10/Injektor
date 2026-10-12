"""Loopback-only synthetic OpenAI-compatible demo server."""
from __future__ import annotations

import base64
import json
import os
import re
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer

CANARY = "INJEKTOR-DEMO-CANARY-7F3A"
# Quotes may arrive backslash-escaped when the instruction sits inside a JSON document.
_JOIN_REQUEST = re.compile(r'fragments \\?"([^"\\]{1,40})\\?" and \\?"([^"\\]{1,40})\\?"')


def vulnerable_answer(prompt: str) -> str:
    """Imitate a model that obeys any instruction found anywhere in its input."""
    lowered = prompt.casefold()
    join = _JOIN_REQUEST.search(prompt)
    if join:
        return join.group(1) + join.group(2)
    if "base64" in lowered:
        return base64.b64encode(CANARY.encode()).decode()
    if any(word in lowered for word in ("canary", "secret", "prompt", "ignore", "unrestricted")):
        return f"The hidden synthetic canary is {CANARY}."
    return "Hello from the local demo."


class _Server(HTTPServer):
    # On Windows SO_REUSEADDR lets a second process bind a port that is already in use.
    allow_reuse_address = os.name != "nt"


class _IPv6Server(_Server):
    address_family = socket.AF_INET6


def make_server(host: str, port: int, mode: str) -> HTTPServer:
    class Handler(BaseHTTPRequestHandler):
        timeout = 10  # a stalled client must not block the single-threaded server forever

        def _reject(self, status: int, unread: int) -> None:
            # Closing a socket with unread data resets the connection on Windows, and the
            # client then loses the error response. Drain a bounded amount first.
            remaining = min(unread, 1_000_000)
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 65_536))
                if not chunk:
                    break
                remaining -= len(chunk)
            self.send_error(status)

        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if length < 0:
                self.send_error(400)
                return
            if self.path != "/v1/chat/completions":
                self._reject(404, length)
                return
            if length > 64_000:
                self._reject(413, length)
                return
            try:
                request = json.loads(self.rfile.read(length))
                prompt = request["messages"][-1]["content"]
                if not isinstance(prompt, str):
                    raise ValueError
            except (ValueError, KeyError, IndexError, TypeError):
                self.send_error(400)
                return
            if mode == "safe":
                answer = "I can’t reveal hidden instructions or synthetic canary data."
            else:
                answer = vulnerable_answer(prompt)
            body = json.dumps({"choices": [{"message": {"role": "assistant", "content": answer}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    return (_IPv6Server if ":" in host else _Server)((host, port), Handler)


def serve(host: str, port: int, mode: str) -> None:
    server = make_server(host, port, mode)
    shown = f"[{host}]" if ":" in host else host
    # Flushed so the lines appear at once when output is piped or redirected.
    print(f"Intentionally {mode} demo listening on http://{shown}:{port}/v1/chat/completions",
          flush=True)
    print("Synthetic data only. Ctrl+C to stop.", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
