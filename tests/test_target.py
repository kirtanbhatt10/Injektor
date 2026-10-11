import json

import httpx
import pytest

from injector.config import TargetConfig
from injector.target import OpenAICompatibleTarget, TargetError


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
    import injector.target as target_module

    monkeypatch.setattr(target_module.time, "sleep", lambda _s: None)
    monkeypatch.delenv("INJECTOR_API_KEY", raising=False)


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


def test_slow_drip_body_hits_total_deadline(monkeypatch):
    import injector.target as target_module

    clock = iter(range(0, 100_000, 4))  # every clock read advances four seconds
    monkeypatch.setattr(target_module.time, "monotonic", lambda: next(clock))

    def drip():
        for _ in range(1_000):
            yield b" "

    with pytest.raises(TargetError, match="ReadTimeout"):
        _target(lambda _r: httpx.Response(200, content=drip()), timeout=10.0, retries=0).ask("hello")


@pytest.mark.parametrize("key", ["FAKE-KEY\r\nX-Injected: 1", "FAKE-KEY-é"])
def test_unusable_api_key_is_rejected_without_echoing_it(monkeypatch, key):
    monkeypatch.setenv("INJECTOR_API_KEY", key)
    sent = []

    def handler(request):
        sent.append(request)
        return httpx.Response(200, json={})

    with pytest.raises(TargetError) as excinfo:
        _target(handler).ask("hello")
    assert "FAKE-KEY" not in str(excinfo.value)
    assert sent == []


def test_api_key_is_sent_as_bearer_token(monkeypatch):
    monkeypatch.setenv("INJECTOR_API_KEY", "FAKE-KEY-123")
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("Authorization")
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    assert _target(handler).ask("hello") == "ok"
    assert seen["auth"] == "Bearer FAKE-KEY-123"
