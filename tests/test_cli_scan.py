import hashlib
import json

import httpx
import pytest
from typer.testing import CliRunner

import injektor.cli as cli
from injektor import __version__
from injektor.cli import app
from injektor.config import load_cases
from injektor.target import OpenAICompatibleTarget

CANARY = "INJEKTOR-DEMO-CANARY-7F3A"
SECRET = "FAKE-SECRET-KEY-123"
REFUSAL = "I cannot reveal hidden information."
N = len(load_cases(cli.CASES))  # one request and one result per built-in case


@pytest.fixture
def run_scan(monkeypatch):
    """Run `scan` against an in-process mock target and record every request it receives."""
    def run(reply, *args, endpoint="http://127.0.0.1:8765/v1/chat/completions"):
        requests = []

        def handler(request):
            requests.append(request)
            answer = reply(len(requests)) if callable(reply) else reply
            if isinstance(answer, Exception):
                raise answer
            return httpx.Response(200, json={"choices": [{"message": {"content": answer}}]})

        transport = httpx.MockTransport(handler)
        monkeypatch.setattr(cli, "OpenAICompatibleTarget",
                            lambda cfg: OpenAICompatibleTarget(cfg, transport=transport))
        monkeypatch.setenv("INJEKTOR_ENDPOINT", endpoint)
        monkeypatch.setenv("INJEKTOR_MODEL", "mock-model")
        monkeypatch.setenv("INJEKTOR_RETRIES", "0")
        monkeypatch.delenv("INJEKTOR_API_KEY", raising=False)
        result = CliRunner().invoke(app, ["scan", *args])
        return result, requests

    return run


def load(output):
    return json.loads((output / "report.json").read_text(encoding="utf-8"))


def test_scan_writes_json_and_html(tmp_path, run_scan):
    output = tmp_path / "reports"
    result, _ = run_scan(REFUSAL, "--output", str(output))
    assert result.exit_code == 0, result.output
    report = load(output)
    assert report["statistics"]["total"] == N
    assert (output / "report.html").exists()
    shown = CliRunner().invoke(app, ["report", str(output / "report.json")])
    assert shown.exit_code == 0
    summary = json.loads(shown.stdout)
    assert summary["statistics"] == report["statistics"]
    assert summary["provenance"] == report["provenance"]


def test_scan_exits_zero_without_findings(tmp_path, run_scan):
    result, requests = run_scan(REFUSAL, "--output", str(tmp_path))
    assert result.exit_code == 0, result.output
    assert len(requests) == N
    assert f"{N} inconclusive" in result.output
    assert load(tmp_path)["statistics"]["outcomes"] == {
        "confirmed": 0, "potential": 0, "inconclusive": N, "error": 0}


def test_scan_exits_zero_for_potential_only(tmp_path, run_scan):
    result, _ = run_scan("My system prompt is: You are a bank assistant.", "--output", str(tmp_path))
    outcomes = load(tmp_path)["statistics"]["outcomes"]
    assert outcomes["potential"] >= 1
    assert outcomes["confirmed"] == 0 and outcomes["error"] == 0
    assert result.exit_code == 0, result.output


def test_scan_exits_one_on_confirmed_finding(tmp_path, run_scan):
    result, _ = run_scan(f"The token is {CANARY}.", "--output", str(tmp_path))
    assert result.exit_code == 1, result.output
    assert load(tmp_path)["statistics"]["outcomes"]["confirmed"] == N


def test_scan_exits_three_on_operational_error(tmp_path, run_scan):
    result, _ = run_scan(httpx.ConnectError("refused"), "--output", str(tmp_path))
    assert result.exit_code == 3, result.output
    assert load(tmp_path)["statistics"]["outcomes"]["error"] == N


def test_scan_exits_three_when_only_some_cases_error(tmp_path, run_scan):
    result, _ = run_scan(lambda n: httpx.ConnectError("refused") if n == 2 else REFUSAL,
                         "--output", str(tmp_path))
    assert result.exit_code == 3, result.output
    assert load(tmp_path)["statistics"]["outcomes"] == {
        "confirmed": 0, "potential": 0, "inconclusive": N - 1, "error": 1}


def test_confirmed_finding_takes_precedence_over_errors(tmp_path, run_scan):
    result, _ = run_scan(lambda n: httpx.ConnectError("refused") if n == 1 else f"leak {CANARY}",
                         "--output", str(tmp_path))
    assert result.exit_code == 1, result.output
    assert load(tmp_path)["statistics"]["outcomes"] == {
        "confirmed": N - 1, "potential": 0, "inconclusive": 0, "error": 1}


def test_scan_exits_two_on_invalid_configuration(tmp_path, monkeypatch):
    monkeypatch.delenv("INJEKTOR_ENDPOINT", raising=False)
    monkeypatch.setenv("INJEKTOR_MODEL", "mock-model")
    result = CliRunner().invoke(app, ["scan", "--output", str(tmp_path)])
    assert result.exit_code == 2
    assert not (tmp_path / "report.json").exists()


def test_scan_exits_three_when_report_cannot_be_written(tmp_path, run_scan, monkeypatch):
    """A failure that cannot be foreseen: the outcome counts are still printed."""
    def fail(*_args, **_kwargs):
        raise PermissionError("disk says no")

    monkeypatch.setattr(cli, "write_report", fail)
    result, requests = run_scan(REFUSAL, "--output", str(tmp_path / "out"))
    assert result.exit_code == 3, result.output
    assert len(requests) == N
    assert f"{N} cases: " in result.output and "Could not write report" in result.output


@pytest.mark.parametrize("overwrite", [[], ["--overwrite"]], ids=["plain", "overwrite"])
@pytest.mark.parametrize("below", ["", "reports", "a/b/reports"], ids=["is-file", "child", "deep"])
def test_output_path_blocked_by_a_file_is_refused_before_contacting_the_target(
        tmp_path, run_scan, below, overwrite):
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("keep me", encoding="utf-8")
    result, requests = run_scan(REFUSAL, "--output", str(blocker / below), *overwrite)
    assert result.exit_code == 2, result.output
    assert requests == []
    assert "not a directory" in " ".join(result.output.split())
    assert blocker.read_text(encoding="utf-8") == "keep me"


def test_output_directory_that_does_not_exist_yet_is_created(tmp_path, run_scan):
    output = tmp_path / "new" / "nested" / "reports"
    result, requests = run_scan(REFUSAL, "--output", str(output))
    assert result.exit_code == 0, result.output
    assert len(requests) == N and (output / "report.json").exists()


def test_report_hash_describes_the_case_file_that_was_loaded(tmp_path, run_scan):
    """The file is replaced while the scan runs; the report must not claim the new content."""
    cases = tmp_path / "cases.yaml"
    loaded = cli.CASES.read_bytes()
    cases.write_bytes(loaded)

    def reply(number):
        if number == 1:
            cases.write_bytes(b"- replaced: after loading\n")
        return REFUSAL

    output = tmp_path / "out"
    result, requests = run_scan(reply, "--cases", str(cases), "--output", str(output))
    assert result.exit_code == 0, result.output
    recorded = load(output)["provenance"]["cases"]
    assert recorded == {"file": "cases.yaml", "count": N,
                        "sha256": hashlib.sha256(loaded).hexdigest()}
    assert recorded["sha256"] != hashlib.sha256(cases.read_bytes()).hexdigest()
    assert len(requests) == N


def test_case_file_deleted_during_the_scan_does_not_lose_the_report(tmp_path, run_scan):
    cases = tmp_path / "cases.yaml"
    cases.write_bytes(cli.CASES.read_bytes())

    def reply(number):
        if number == 1:
            cases.unlink()
        return REFUSAL

    result, _ = run_scan(reply, "--cases", str(cases), "--output", str(tmp_path / "out"))
    assert result.exit_code == 0, result.output
    assert (tmp_path / "out" / "report.json").exists()


def test_report_records_provenance(tmp_path, run_scan):
    result, _ = run_scan(REFUSAL, "--output", str(tmp_path))
    assert result.exit_code == 0, result.output
    provenance = load(tmp_path)["provenance"]
    assert provenance["tool"] == {"name": "injektor", "version": __version__}
    assert provenance["target"] == {
        "endpoint": "http://127.0.0.1:8765/v1/chat/completions", "query_redacted": False,
        "model": "mock-model", "credential_supplied": False}
    assert provenance["cases"] == {
        "file": "default.yaml", "count": N,
        "sha256": hashlib.sha256(cli.CASES.read_bytes()).hexdigest()}
    assert provenance["settings"] == {"timeout_seconds": 15.0, "retries": 0,
                                      "delay_seconds": 0.0}
    assert provenance["started_at"] <= provenance["finished_at"]
    page = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "mock-model" in page and provenance["cases"]["sha256"] in page


def test_provenance_never_contains_secrets_or_local_paths(tmp_path, run_scan, monkeypatch):
    monkeypatch.setenv("INJEKTOR_API_KEY_ENV", "MY_PRIVATE_KEY_VARIABLE")
    monkeypatch.setenv("MY_PRIVATE_KEY_VARIABLE", SECRET)
    cases = tmp_path / "private-dir" / "cases.yaml"
    cases.parent.mkdir()
    cases.write_bytes(cli.CASES.read_bytes())
    output = tmp_path / "out"
    result, requests = run_scan(
        REFUSAL, "--output", str(output), "--cases", str(cases),
        endpoint="https://gateway.example.com/v1/chat/completions?api-key=QUERY-SECRET-456")
    assert result.exit_code == 0, result.output
    assert requests[0].headers["Authorization"] == f"Bearer {SECRET}"
    assert requests[0].url.query == b"api-key=QUERY-SECRET-456"  # still sent to the target
    target = load(output)["provenance"]["target"]
    assert target["endpoint"] == "https://gateway.example.com/v1/chat/completions"
    assert target["query_redacted"] is True
    assert target["credential_supplied"] is True
    written = "".join((output / name).read_text(encoding="utf-8")
                      for name in ("report.json", "report.html")) + result.output
    for forbidden in (SECRET, "QUERY-SECRET-456", "MY_PRIVATE_KEY_VARIABLE", "private-dir"):
        assert forbidden not in written


def test_provenance_is_html_escaped(tmp_path):
    from injektor.config import TargetConfig
    from injektor.reporting import build_provenance, write_report

    hostile = "<script>alert(1)</script>"
    config = TargetConfig("http://127.0.0.1:8765/v1", hostile)
    provenance = build_provenance(config, cli.CASES, 4, "2026-01-01T00:00:00+00:00", "ab" * 32)
    _, html_path = write_report([], tmp_path, provenance)
    page = html_path.read_text(encoding="utf-8")
    assert "<script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


@pytest.mark.parametrize("existing", ["report.json", "report.html"])
def test_scan_refuses_to_overwrite_before_contacting_target(tmp_path, run_scan, existing):
    (tmp_path / existing).write_text("previous evidence", encoding="utf-8")
    result, requests = run_scan(f"leak {CANARY}", "--output", str(tmp_path))
    assert result.exit_code == 2
    assert "--overwrite" in result.output
    assert requests == []
    assert (tmp_path / existing).read_text(encoding="utf-8") == "previous evidence"
    assert sorted(p.name for p in tmp_path.iterdir()) == [existing]


@pytest.mark.parametrize("overwrite", [False, True])
def test_scan_exits_three_and_keeps_old_reports_when_publishing_fails(tmp_path, run_scan,
                                                                      monkeypatch, overwrite):
    import injektor.reporting as reporting

    old = {"report.json": b"old json", "report.html": b"old html"} if overwrite else {}
    for name, content in old.items():
        (tmp_path / name).write_bytes(content)
    real, calls = reporting.os.replace, []

    def fail_last(source, destination):
        calls.append(str(destination))
        if str(source).endswith(".tmp") and str(destination).endswith("report.html"):
            raise OSError("simulated disk failure")
        return real(source, destination)

    monkeypatch.setattr(reporting.os, "replace", fail_last)
    args = ["--output", str(tmp_path)] + (["--overwrite"] if overwrite else [])
    result, requests = run_scan(f"leak {CANARY}", *args)
    assert result.exit_code == 3, result.output
    assert len(requests) == N
    assert f"{N} confirmed" in result.output  # findings are still reported on the console
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == old


def test_scan_overwrites_only_when_asked(tmp_path, run_scan):
    first, _ = run_scan(REFUSAL, "--output", str(tmp_path))
    assert first.exit_code == 0, first.output
    second, _ = run_scan(f"leak {CANARY}", "--output", str(tmp_path), "--overwrite")
    assert second.exit_code == 1, second.output
    assert load(tmp_path)["statistics"]["outcomes"]["confirmed"] == N
    assert CANARY in (tmp_path / "report.html").read_text(encoding="utf-8")


def test_unexpected_failure_is_not_reported_as_a_confirmed_finding(tmp_path, run_scan, monkeypatch):
    def explode(*_args, **_kwargs):
        raise RuntimeError(f"bug while holding {SECRET}")

    monkeypatch.setattr(cli, "detect", explode)
    result, _ = run_scan(REFUSAL, "--output", str(tmp_path))
    assert result.exit_code == 3, result.output
    assert "RuntimeError" in result.output
    assert SECRET not in result.output
    assert list(tmp_path.iterdir()) == []


def test_interrupted_scan_is_not_reported_as_a_confirmed_finding(tmp_path, run_scan):
    def interrupt(_request_number):
        raise KeyboardInterrupt

    result, requests = run_scan(interrupt, "--output", str(tmp_path))
    assert len(requests) == 1
    assert result.exit_code == 130
    assert list(tmp_path.iterdir()) == []


def test_unencodable_text_in_a_case_file_still_produces_a_report(tmp_path, run_scan):
    case_id = "bad" + chr(0xD800) + "id"
    cases = tmp_path / "cases.yaml"
    cases.write_text('- id: "bad\\ud800id"\n  category: c\n  description: d\n  test_input: t\n'
                     '  expected_safe_behavior: e\n  severity: high\n', encoding="utf-8")
    output = tmp_path / "out"
    result, requests = run_scan(REFUSAL, "--cases", str(cases), "--output", str(output))
    assert result.exit_code == 0, result.output
    assert len(requests) == 1
    assert load(output)["results"][0]["test_id"] == case_id
    assert sorted(p.name for p in output.iterdir()) == ["report.html", "report.json"]
