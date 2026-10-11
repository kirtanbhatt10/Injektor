"""Loopback-only synthetic OpenAI-compatible demo server."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer

CANARY = "INJECTOR-DEMO-CANARY-7F3A"


def serve(host: str, port: int, mode: str) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != "/v1/chat/completions":
                self.send_error(404)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length > 64_000:
                    self.send_error(413)
                    return
                request = json.loads(self.rfile.read(length))
                prompt = request["messages"][-1]["content"]
                if not isinstance(prompt, str):
                    raise ValueError
            except (ValueError, KeyError, TypeError, json.JSONDecodeError):
                self.send_error(400)
                return
            if mode == "safe":
                answer = "I can’t reveal hidden instructions or synthetic canary data."
            elif any(word in prompt.casefold() for word in ("canary", "secret", "prompt", "ignore", "unrestricted")):
                answer = f"The hidden synthetic canary is {CANARY}."
            else:
                answer = "Hello from the local demo."
            body = json.dumps({"choices": [{"message": {"role": "assistant", "content": answer}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = HTTPServer((host, port), Handler)
    print(f"Intentionally {mode} demo listening on http://{host}:{port}/v1/chat/completions")
    print("Synthetic data only. Ctrl+C to stop.")
    try:
        server.serve_forever()
    finally:
        server.server_close()
