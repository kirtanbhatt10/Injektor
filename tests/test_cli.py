import json

import httpx
import pytest
from typer.testing import CliRunner

import injektor.cli as cli
from injektor.cli import app

CASE = ("- id: a\n  category: c\n  description: d\n  test_input: t\n"
        "  expected_safe_behavior: e\n  severity: high\n")


def test_list_command_runs():
    result = CliRunner().invoke(app, ["list"])
    assert result.exit_code == 0
    assert "direct-override" in result.stdout
    assert result.stdout.isascii()  # must survive legacy Windows console code pages


def test_tracebacks_never_render_locals():
    # Frames under scan hold the Authorization header; rich must not print them.
    assert app.pretty_exceptions_show_locals is False


def test_scan_records_transport_failure_without_leaking_the_key(tmp_path, monkeypatch):
    def handler(_request):
        raise httpx.RemoteProtocolError("peer sent garbage")

    real = cli.OpenAICompatibleTarget
    monkeypatch.setattr(cli, "OpenAICompatibleTarget",
                        lambda cfg: real(cfg, transport=httpx.MockTransport(handler)))
    monkeypatch.setenv("INJEKTOR_ENDPOINT", "http://127.0.0.1:8765/v1/chat/completions")
    monkeypatch.setenv("INJEKTOR_MODEL", "mock")
    monkeypatch.setenv("INJEKTOR_RETRIES", "0")
    monkeypatch.setenv("INJEKTOR_API_KEY", "FAKE-SECRET-KEY-123")
    result = CliRunner().invoke(app, ["scan", "--output", str(tmp_path)])
    assert result.exit_code == 3, result.output  # every case failed: operational error
    assert "FAKE-SECRET-KEY-123" not in result.output
    for name in ("report.json", "report.html"):
        assert "FAKE-SECRET-KEY-123" not in (tmp_path / name).read_text(encoding="utf-8")
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["statistics"]["outcomes"]["error"] == 4


def test_scan_rejects_case_file_with_invalid_regex(tmp_path, monkeypatch):
    cases = tmp_path / "cases.yaml"
    cases.write_text(CASE + "  indicators: ['(x']\n", encoding="utf-8")
    monkeypatch.setenv("INJEKTOR_ENDPOINT", "http://127.0.0.1:8765/v1/chat/completions")
    monkeypatch.setenv("INJEKTOR_MODEL", "mock")
    out = tmp_path / "out"
    result = CliRunner().invoke(app, ["scan", "--cases", str(cases), "--output", str(out)])
    assert result.exit_code == 2
    assert isinstance(result.exception, SystemExit)
    assert not out.exists()


@pytest.mark.parametrize("content", [b"[1, 2]", b'{"statistics": 3}', b"\xff\xfe\x00", b"not json"])
def test_report_rejects_files_that_are_not_reports(tmp_path, content):
    path = tmp_path / "report.json"
    path.write_bytes(content)
    result = CliRunner().invoke(app, ["report", str(path)])
    assert result.exit_code == 2
    assert isinstance(result.exception, SystemExit)


def test_demo_refuses_non_loopback_host():
    result = CliRunner().invoke(app, ["demo", "--host", "0.0.0.0"])
    assert result.exit_code == 2
