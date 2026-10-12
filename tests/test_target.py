import itertools
import json
import socket
import threading
import time

import httpx
import pytest

from injektor.config import TargetConfig
from injektor.target import OpenAICompatibleTarget, TargetError


def test_mocked_endpoint_roundtrip():
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": "local mock response"}}]})

    transport = httpx.MockTransport(handler)
    cfg = TargetConfig("http://127.0.0.1:8765/v1/chat/completions", "mock")
    assert OpenAICompatibleTarget(cfg, transport=transport).ask("hello") == "local mock response"
    assert seen["body"]["messages"][0]["content"] == "hello"


def _target(handler, **overrides):
    cfg = TargetConfig("http://127.0.0.1:8765/v1/chat/completions", "mock", **overrides)
    return OpenAICompatibleTarget(cfg, transport=httpx.MockTransport(handler))


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch):
    import injektor.target as target_module

    monkeypatch.setattr(target_module.time, "sleep", lambda _s: None)
    monkeypatch.delenv("INJEKTOR_API_KEY", raising=False)


@pytest.mark.parametrize("exc", [httpx.RemoteProtocolError("boom"), httpx.DecodingError("boom"),
                                 httpx.ProxyError("boom"), httpx.InvalidURL("boom")])
def test_transport_failures_become_target_errors(exc):
    calls = []

    def handler(_request):
        calls.append(1)
        raise exc

    with pytest.raises(TargetError, match=type(exc).__name__):
        _target(handler, retries=2).ask("hello")
    assert len(calls) == 3  # one attempt plus exactly the configured retries


def test_deeply_nested_json_is_a_target_error():
    with pytest.raises(TargetError):
        _target(lambda _r: httpx.Response(200, content=b"[" * 200_000), retries=0).ask("hello")


def test_oversized_response_is_rejected():
    with pytest.raises(TargetError, match="1 MB"):
        _target(lambda _r: httpx.Response(200, content=b" " * 1_000_001), retries=0).ask("hello")


def test_redirects_are_not_followed():
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(302, headers={"Location": "http://127.0.0.1:1/elsewhere"})

    with pytest.raises(TargetError, match="redirect"):
        _target(handler).ask("hello")
    assert calls == ["http://127.0.0.1:8765/v1/chat/completions"]


@pytest.fixture
def dripping_server():
    """A real loopback server that reads each request and then sends the pieces that
    `pieces()` yields one at a time, `interval` seconds apart. Every piece arrives well inside the per-operation socket
    timeout, so only a deadline on the whole request can end the exchange."""
    started = []

    def start(pieces, interval=0.1):
        try:
            listener = socket.create_server(("127.0.0.1", 0))
        except OSError as exc:  # sandboxed runners may forbid sockets
            pytest.skip(f"cannot bind 127.0.0.1: {exc}")
        stop, connections = threading.Event(), []

        def serve():
            while True:
                try:
                    connection, _address = listener.accept()
                except OSError:
                    return
                connections.append(connection)
                threading.Thread(target=drip, args=(connection,), daemon=True).start()

        def drip(connection):
            with connection:
                try:
                    connection.recv(65_536)
                    for piece in pieces():
                        if stop.wait(interval):
                            return
                        connection.sendall(piece)
                    stop.wait(60)  # then say nothing more and keep the connection open
                except OSError:
                    pass

        threading.Thread(target=serve, daemon=True).start()
        started.append((listener, stop))
        port = listener.getsockname()[1]
        return f"http://127.0.0.1:{port}/v1/chat/completions", connections

    yield start
    for listener, stop in started:
        stop.set()
        listener.close()


def headers_forever():
    return itertools.chain([b"HTTP/1.1 200 OK\r\n"], itertools.repeat(b"X-Pad: aaaaaaaa\r\n"))


def body_forever():
    return itertools.chain(
        [b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 900000\r\n\r\n"],
        itertools.repeat(b" "))


def status_line_byte_by_byte():
    return (b"HTTP/1.1 200 OK"[i:i + 1] for i in range(15))


def nothing():
    return ()


def _timed(url, **overrides):
    """Seconds until ask() gave up, and the error it raised."""
    adapter = OpenAICompatibleTarget(TargetConfig(url, "mock", **overrides))
    started = time.monotonic()
    try:
        with pytest.raises(TargetError) as excinfo:
            adapter.ask("hello")
    finally:
        adapter.close()
    return time.monotonic() - started, str(excinfo.value)


@pytest.mark.parametrize("pieces", [headers_forever, body_forever, status_line_byte_by_byte,
                                    nothing], ids=lambda function: function.__name__)
def test_whole_request_is_bounded_by_the_deadline(dripping_server, pieces):
    url, connections = dripping_server(pieces)
    elapsed, message = _timed(url, timeout=1.0, retries=0)
    # Without a whole-request deadline the first three would run for minutes or for ever.
    assert 0.9 <= elapsed < 4.0, (elapsed, message)
    assert "request deadline" in message or "ReadTimeout" in message
    assert len(connections) == 1


def test_slow_headers_are_stopped_by_the_deadline_not_by_the_socket_timeout(dripping_server):
    url, _connections = dripping_server(headers_forever)
    elapsed, message = _timed(url, timeout=1.0, retries=0)
    assert message == "Target did not answer within the 1-second request deadline."
    assert elapsed < 4.0


def test_deadline_applies_to_each_attempt_and_retries_stay_bounded(dripping_server):
    url, connections = dripping_server(headers_forever)
    elapsed, message = _timed(url, timeout=1.0, retries=2)
    assert "request deadline" in message
    assert len(connections) == 3
    assert 2.7 <= elapsed < 9.0, elapsed  # three attempts of one second each


def test_answer_that_arrives_inside_the_deadline_is_returned(dripping_server):
    body = b'{"choices": [{"message": {"content": "slow but fine"}}]}'
    head = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
            + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n")
    url, _connections = dripping_server(lambda: [head, body[:20], body[20:]], interval=0.15)
    adapter = OpenAICompatibleTarget(TargetConfig(url, "mock", timeout=5.0, retries=0))
    try:
        assert adapter.ask("hello") == "slow but fine"
        assert adapter.ask("again") == "slow but fine"  # the adapter is reusable
    finally:
        adapter.close()


def test_adapter_can_be_closed_twice_and_before_use():
    adapter = _target(lambda _r: httpx.Response(200, json={}))
    adapter.close()
    adapter.close()


@pytest.mark.parametrize("key", ["FAKE-KEY\r\nX-Injected: 1", "FAKE-KEY-é"])
def test_unusable_api_key_is_rejected_without_echoing_it(monkeypatch, key):
    monkeypatch.setenv("INJEKTOR_API_KEY", key)
    sent = []

    def handler(request):
        sent.append(request)
        return httpx.Response(200, json={})

    with pytest.raises(TargetError) as excinfo:
        _target(handler).ask("hello")
    assert "FAKE-KEY" not in str(excinfo.value)
    assert sent == []


def test_api_key_is_sent_as_bearer_token(monkeypatch):
    monkeypatch.setenv("INJEKTOR_API_KEY", "FAKE-KEY-123")
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("Authorization")
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    assert _target(handler).ask("hello") == "ok"
    assert seen["auth"] == "Bearer FAKE-KEY-123"
