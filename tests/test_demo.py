"""End-to-end checks against the real demo server on an ephemeral loopback port."""
import json
import threading

import httpx
import pytest
from typer.testing import CliRunner

from injector.cli import app
from injector.demo import make_server


@pytest.fixture
def demo():
    servers = []

    def start(mode, host="127.0.0.1"):
        try:
            server = make_server(host, 0, mode)
        except OSError as exc:  # sandboxed runners may forbid sockets or lack IPv6
            pytest.skip(f"cannot bind {host}: {exc}")
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        shown = f"[{host}]" if ":" in host else host
        return f"http://{shown}:{server.server_address[1]}/v1/chat/completions"

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def scan(url, tmp_path, monkeypatch):
    monkeypatch.setenv("INJECTOR_ENDPOINT", url)
    monkeypatch.setenv("INJECTOR_MODEL", "injector-demo")
    monkeypatch.delenv("INJECTOR_API_KEY", raising=False)
    result = CliRunner().invoke(app, ["scan", "--output", str(tmp_path)])
    assert result.exit_code == 0, result.output
    return json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))


def test_vulnerable_demo_confirms_every_case(demo, tmp_path, monkeypatch):
    report = scan(demo("vulnerable"), tmp_path, monkeypatch)
    assert report["statistics"]["outcomes"] == {
        "confirmed": 4, "potential": 0, "inconclusive": 0, "error": 0}


def test_safe_demo_raises_no_findings(demo, tmp_path, monkeypatch):
    report = scan(demo("safe"), tmp_path, monkeypatch)
    assert report["statistics"]["outcomes"] == {
        "confirmed": 0, "potential": 0, "inconclusive": 4, "error": 0}
    assert report["statistics"]["indicator_score"] == 0


def test_demo_serves_ipv6_loopback(demo, tmp_path, monkeypatch):
    report = scan(demo("vulnerable", host="::1"), tmp_path, monkeypatch)
    assert report["statistics"]["outcomes"]["confirmed"] == 4


def test_demo_port_cannot_be_bound_twice(demo):
    port = int(demo("safe").rsplit(":", 1)[1].split("/")[0])
    with pytest.raises(OSError):
        make_server("127.0.0.1", port, "vulnerable").server_close()


@pytest.mark.parametrize("kwargs,status", [
    ({"json": {"messages": []}}, 400),
    ({"json": {"messages": [{"content": 5}]}}, 400),
    ({"content": b"not json"}, 400),
    ({"content": b"x" * 64_001}, 413),
])
def test_demo_rejects_malformed_requests_and_keeps_serving(demo, kwargs, status):
    url = demo("vulnerable")
    with httpx.Client(trust_env=False, timeout=5) as client:
        assert client.post(url, **kwargs).status_code == status
        ok = client.post(url, json={"messages": [{"role": "user", "content": "hi"}]})
        assert ok.json()["choices"][0]["message"]["content"] == "Hello from the local demo."
        assert client.post(url.replace("/v1/", "/v2/"), json={}).status_code == 404
