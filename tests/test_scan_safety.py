"""Bounded, predictable behavior towards the target, and errors that never become findings."""
import json
import time
import types

import httpx
import pytest
from typer.testing import CliRunner

import injektor.cli as cli
import injektor.target as target_module
from injektor import __version__
from injektor.cli import MAX_CONSECUTIVE_ERRORS, app
from injektor.config import TargetConfig, load_cases
from injektor.target import (MAX_CONTENT_CHARS, MAX_RETRY_AFTER_SECONDS, AuthenticationRejected,
                             OpenAICompatibleTarget, TargetError)

N = len(load_cases(cli.CASES))
CANARY = "INJEKTOR-DEMO-CANARY-7F3A"
SECRET = "FAKE-SECRET-KEY-123"
URL = "http://127.0.0.1:8765/v1/chat/completions"


def completion(text):
    return httpx.Response(200, json={"choices": [{"message": {"content": text}}]})


def fake_time(sleep):
    """A stand-in for the ``time`` module of one injektor module, with ``sleep`` replaced.

    Patching ``time.sleep`` on the real module would also record sleeps from unrelated code,
    such as ``subprocess`` polling while an indicator regex runs in its child interpreter."""
    clock = types.SimpleNamespace(**{name: getattr(time, name) for name in dir(time)
                                     if not name.startswith("_")})
    clock.sleep = sleep
    return clock


def target(handler, **overrides):
    return OpenAICompatibleTarget(TargetConfig(URL, "mock", **overrides),
                                  transport=httpx.MockTransport(handler))


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    sleeps = []
    monkeypatch.setattr(target_module, "time", fake_time(sleeps.append))
    monkeypatch.delenv("INJEKTOR_API_KEY", raising=False)
    monkeypatch.delenv("INJEKTOR_DELAY", raising=False)
    return sleeps


@pytest.fixture
def run_scan(monkeypatch):
    def run(handler, *args, env=None):
        requests = []

        def recording(request):
            requests.append(request)
            return handler(len(requests))

        transport = httpx.MockTransport(recording)
        monkeypatch.setattr(cli, "OpenAICompatibleTarget",
                            lambda cfg: OpenAICompatibleTarget(cfg, transport=transport))
        monkeypatch.setenv("INJEKTOR_ENDPOINT", URL)
        monkeypatch.setenv("INJEKTOR_MODEL", "mock-model")
        monkeypatch.setenv("INJEKTOR_RETRIES", "0")
        for name, value in (env or {}).items():
            monkeypatch.setenv(name, value)
        return CliRunner().invoke(app, ["scan", *args]), requests

    return run


def load(output):
    return json.loads((output / "report.json").read_text(encoding="utf-8"))


# --- retries ---------------------------------------------------------------------------------

@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
def test_transient_statuses_are_retried_up_to_the_limit(status):
    calls = []

    def handler(_request):
        calls.append(1)
        return httpx.Response(status, text=f"upstream said {SECRET}")

    with pytest.raises(TargetError) as excinfo:
        target(handler, retries=2).ask("hello")
    assert len(calls) == 3
    assert f"HTTP {status}" in str(excinfo.value) and SECRET not in str(excinfo.value)


def test_transient_status_followed_by_success_returns_the_answer():
    replies = iter([httpx.Response(503), completion("fine")])
    assert target(lambda _r: next(replies), retries=1).ask("hello") == "fine"


@pytest.mark.parametrize("status,hint", [(400, ""), (401, "API key"), (403, "not permitted"),
                                         (404, "endpoint path"), (422, "")])
def test_permanent_statuses_are_not_retried(status, hint):
    calls = []

    def handler(_request):
        calls.append(1)
        return httpx.Response(status, json={"error": f"bad key {SECRET}"})

    with pytest.raises(TargetError) as excinfo:
        target(handler, retries=3).ask("hello")
    assert calls == [1]  # repeating a rejected request only adds load and risks a lockout
    message = str(excinfo.value)
    assert f"HTTP {status}" in message and hint in message and SECRET not in message


@pytest.mark.parametrize("body", [b"<html>502 Bad Gateway</html>", b"", b"\xff\xfe", b"[" * 200_000],
                         ids=["html", "empty", "not-utf8", "deeply-nested"])
def test_non_json_body_is_reported_once_without_retrying(body):
    calls = []

    def handler(_request):
        calls.append(1)
        return httpx.Response(200, content=body)

    with pytest.raises(TargetError, match="not valid JSON"):
        target(handler, retries=3).ask("hello")
    assert calls == [1]


@pytest.mark.parametrize("payload", [
    {}, [], "text", 5, None, {"choices": []}, {"choices": [{}]}, {"choices": "x"},
    {"choices": [{"message": None}]}, {"choices": [{"message": {"content": None}}]},
    {"choices": [{"message": {"content": 5}}]}, {"choices": [{"message": {"content": []}}]},
    {"choices": [{"message": {"content": [{"type": "image_url", "image_url": "x"}]}}]},
    {"error": {"message": f"invalid key {SECRET}"}},
])
def test_malformed_completions_are_errors_and_never_echo_the_body(payload):
    with pytest.raises(TargetError) as excinfo:
        target(lambda _r: httpx.Response(200, json=payload), retries=0).ask("hello")
    assert SECRET not in str(excinfo.value)


def test_content_parts_array_is_joined():
    parts = [{"type": "text", "text": "first"}, {"type": "image_url", "image_url": {}},
             {"type": "text", "text": "second"}]
    reply = httpx.Response(200, json={"choices": [{"message": {"content": parts}}]})
    assert target(lambda _r: reply).ask("hello") == "first\nsecond"


def test_long_answer_is_truncated_and_flagged():
    adapter = target(lambda _r: completion("x" * (MAX_CONTENT_CHARS + 1)))
    assert len(adapter.ask("hello")) == MAX_CONTENT_CHARS
    assert adapter.last_response_truncated is True
    adapter = target(lambda _r: completion("short"))
    adapter.ask("hello")
    assert adapter.last_response_truncated is False


def test_truncated_answer_is_stated_in_the_evidence_and_fingerprint(tmp_path, run_scan):
    answer = "x" * (MAX_CONTENT_CHARS + 500) + CANARY  # the canary is beyond the examined part
    result, _ = run_scan(lambda _n: completion(answer), "--output", str(tmp_path))
    assert result.exit_code == 0, result.output
    first = load(tmp_path)["results"][0]
    assert first["outcome"] == "inconclusive"
    assert first["response"]["truncated"] is True
    assert first["response"]["characters"] == MAX_CONTENT_CHARS
    assert any("only the first part was examined" in line for line in first["evidence"])


def test_whitespace_only_api_key_sends_no_authorization_header(monkeypatch):
    monkeypatch.setenv("INJEKTOR_API_KEY", "  \n")
    seen = []

    def handler(request):
        seen.append(request.headers.get("Authorization"))
        return completion("ok")

    target(handler).ask("hello")
    assert seen == [None]


# --- scan loop -------------------------------------------------------------------------------

def test_scan_stops_contacting_a_target_that_keeps_failing(tmp_path, run_scan):
    result, requests = run_scan(lambda _n: httpx.Response(500), "--output", str(tmp_path))
    assert result.exit_code == 3, result.output
    assert len(requests) == MAX_CONSECUTIVE_ERRORS < N
    report = load(tmp_path)
    assert report["statistics"]["outcomes"] == {
        "confirmed": 0, "potential": 0, "inconclusive": 0, "error": N}
    evidence = [r["evidence"][0] for r in report["results"]]
    assert all("HTTP 500" in line for line in evidence[:MAX_CONSECUTIVE_ERRORS])
    assert all(line.startswith("Not sent: the scan stopped contacting the target after 3 "
                               "consecutive errors.") for line in evidence[MAX_CONSECUTIVE_ERRORS:])
    assert "First error: Target returned HTTP 500" in result.output
    assert result.output.count("error (not sent)") == N - MAX_CONSECUTIVE_ERRORS


def test_failing_target_receives_a_bounded_number_of_requests(tmp_path, run_scan):
    result, requests = run_scan(lambda _n: httpx.Response(503), "--output", str(tmp_path),
                                env={"INJEKTOR_RETRIES": "3"})
    assert result.exit_code == 3, result.output
    assert len(requests) == MAX_CONSECUTIVE_ERRORS * (1 + 3)


# --- authentication rejection ----------------------------------------------------------------

@pytest.mark.parametrize("status", [401, 403])
def test_rejected_credential_is_sent_exactly_once(tmp_path, run_scan, status):
    result, requests = run_scan(lambda _n: httpx.Response(status), "--output", str(tmp_path),
                                env={"INJEKTOR_API_KEY": SECRET, "INJEKTOR_RETRIES": "3"})
    assert result.exit_code == 3, result.output
    assert [r.headers.get("Authorization") for r in requests] == [f"Bearer {SECRET}"]
    report = load(tmp_path)
    assert report["statistics"]["outcomes"]["error"] == N
    evidence = [r["evidence"][0] for r in report["results"]]
    assert f"HTTP {status}" in evidence[0]
    assert all(line.startswith("Not sent: the target rejected the request") for line in evidence[1:])
    assert result.output.count("error (not sent)") == N - 1
    assert SECRET not in result.output + (tmp_path / "report.json").read_text(encoding="utf-8")


def test_rejection_in_the_middle_of_a_scan_stops_it_there(tmp_path, run_scan):
    def handler(number):
        return httpx.Response(403) if number == 4 else completion("I cannot help with that.")

    result, requests = run_scan(handler, "--output", str(tmp_path),
                                env={"INJEKTOR_API_KEY": SECRET})
    assert result.exit_code == 3, result.output
    assert len(requests) == 4
    outcomes = [r["outcome"] for r in load(tmp_path)["results"]]
    assert outcomes == ["inconclusive"] * 3 + ["error"] * (N - 3)


@pytest.mark.parametrize("status", [401, 403])
def test_adapter_reports_rejection_as_its_own_error_type(status):
    calls = []

    def handler(_request):
        calls.append(1)
        return httpx.Response(status, headers={"Retry-After": "1"})

    with pytest.raises(AuthenticationRejected, match=f"HTTP {status}"):
        target(handler, retries=3).ask("hello")
    assert calls == [1]


# --- rate limits -----------------------------------------------------------------------------

def rate_limited(retry_after, then="fine"):
    replies = iter([httpx.Response(429, headers={"Retry-After": retry_after}), completion(then)])
    return lambda _request: next(replies)


def http_date(seconds_from_now):
    from datetime import datetime, timedelta, timezone
    from email.utils import format_datetime
    return format_datetime(datetime.now(timezone.utc) + timedelta(seconds=seconds_from_now),
                           usegmt=True)


@pytest.mark.parametrize("header,expected", [("7", 7.0), ("30", 30.0), (" 12 ", 12.0)])
def test_retry_after_seconds_are_honoured(_quiet, header, expected):
    assert target(rate_limited(header), retries=1).ask("hello") == "fine"
    assert _quiet == [expected]


def test_retry_after_http_date_is_honoured(_quiet):
    assert target(rate_limited(http_date(10)), retries=1).ask("hello") == "fine"
    assert len(_quiet) == 1 and 8.0 <= _quiet[0] <= 10.0


@pytest.mark.parametrize("header", ["0", "soon", "-5", "1.5", "", "7, 9", http_date(-3600)],
                         ids=["zero", "word", "negative", "fraction", "empty", "list", "past"])
def test_missing_or_invalid_retry_after_falls_back_to_the_short_pause(_quiet, header):
    assert target(rate_limited(header), retries=1).ask("hello") == "fine"
    assert _quiet == [0.2]


@pytest.mark.parametrize("header", ["31", "86400", "9" * 400, http_date(3600)],
                         ids=["just-over", "a-day", "huge", "date-in-an-hour"])
def test_retry_after_beyond_the_limit_is_not_waited_for_and_not_retried(_quiet, header):
    calls = []

    def handler(_request):
        calls.append(1)
        return httpx.Response(429, headers={"Retry-After": header})

    with pytest.raises(TargetError, match="Retry-After") as excinfo:
        target(handler, retries=3).ask("hello")
    assert calls == [1] and _quiet == []
    assert not isinstance(excinfo.value, AuthenticationRejected)


def test_rate_limit_waits_are_bounded_by_the_retry_count(_quiet):
    calls = []

    def handler(_request):
        calls.append(1)
        return httpx.Response(429, headers={"Retry-After": "30"})

    with pytest.raises(TargetError, match="HTTP 429"):
        target(handler, retries=3).ask("hello")
    assert len(calls) == 4
    assert _quiet == [MAX_RETRY_AFTER_SECONDS] * 3


def test_retry_after_is_read_for_429_only(_quiet):
    replies = iter([httpx.Response(503, headers={"Retry-After": "25"}), completion("fine")])
    assert target(lambda _r: next(replies), retries=1).ask("hello") == "fine"
    assert _quiet == [0.2]


def test_isolated_errors_do_not_stop_the_scan(tmp_path, run_scan):
    def handler(number):
        return httpx.Response(500) if number % 2 else completion("I cannot help with that.")

    result, requests = run_scan(handler, "--output", str(tmp_path))
    assert result.exit_code == 3, result.output
    assert len(requests) == N
    assert load(tmp_path)["statistics"]["outcomes"]["error"] == N // 2


@pytest.mark.parametrize("handler", [
    lambda _n: httpx.Response(200, content=b"not json " + CANARY.encode()),
    lambda _n: httpx.Response(500, text=CANARY),
    lambda _n: httpx.Response(302, headers={"Location": f"http://127.0.0.1/{CANARY}"}),
    lambda _n: httpx.Response(200, json={"error": CANARY}),
])
def test_error_responses_mentioning_the_canary_are_errors_not_findings(tmp_path, run_scan, handler):
    result, _ = run_scan(handler, "--output", str(tmp_path))
    assert result.exit_code == 3, result.output
    report = load(tmp_path)
    assert report["statistics"]["outcomes"]["error"] == N
    assert report["statistics"]["indicator_score"] == 0
    assert CANARY not in json.dumps(report["results"][0]["evidence"])
    assert all("remediation" not in r and "excerpts" not in r for r in report["results"])


def test_delay_is_applied_between_requests_only(tmp_path, run_scan, monkeypatch):
    pauses = []
    monkeypatch.setattr(cli, "time", fake_time(pauses.append))
    result, requests = run_scan(lambda _n: completion("no"), "--output", str(tmp_path),
                                env={"INJEKTOR_DELAY": "1.5"})
    assert result.exit_code == 0, result.output
    assert len(requests) == N and pauses == [1.5] * (N - 1)
    assert load(tmp_path)["provenance"]["settings"]["delay_seconds"] == 1.5


def test_scan_states_the_target_and_progress_without_the_query_string(tmp_path, run_scan):
    result, _ = run_scan(lambda _n: completion("no"), "--output", str(tmp_path),
                         env={"INJEKTOR_ENDPOINT": "https://gw.example.com/v1/chat?api-key=QUERY-SECRET",
                              "INJEKTOR_API_KEY": SECRET})
    assert result.exit_code == 0, result.output
    assert "Target: https://gw.example.com/v1/chat (model mock-model)" in result.output
    assert "authorized" in result.output
    assert f"[{N}/{N}] translation-smuggling" in result.output
    assert "QUERY-SECRET" not in result.output and SECRET not in result.output
    assert "not proof" in result.output


def test_result_records_evidence_fingerprint_and_remediation(tmp_path, run_scan):
    answer = f"Sure, the token is {CANARY}. Anything else?"
    result, _ = run_scan(lambda _n: completion(answer), "--output", str(tmp_path))
    assert result.exit_code == 1, result.output
    first = load(tmp_path)["results"][0]
    assert first["outcome"] == "confirmed"
    assert first["excerpts"] == [answer]
    assert first["response"]["characters"] == len(answer)
    assert len(first["response"]["sha256"]) == 64 and first["response"]["truncated"] is False
    assert first["remediation"] and first["test_input"] and first["expected_safe_behavior"]
    for forbidden in ("Authorization", "Bearer", "headers"):
        assert forbidden not in json.dumps(first)


def test_no_excerpts_keeps_response_text_out_of_both_reports(tmp_path, run_scan):
    answer = f"PRIVATE-CONTEXT-TEXT then {CANARY}"
    result, _ = run_scan(lambda _n: completion(answer), "--output", str(tmp_path), "--no-excerpts")
    assert result.exit_code == 1, result.output
    written = "".join((tmp_path / name).read_text(encoding="utf-8")
                      for name in ("report.json", "report.html"))
    assert "PRIVATE-CONTEXT-TEXT" not in written
    assert all("excerpts" not in r for r in load(tmp_path)["results"])
    assert "Response excerpt" not in (tmp_path / "report.html").read_text(encoding="utf-8")
    for fmt in ("text", "json"):
        shown = CliRunner().invoke(app, ["report", str(tmp_path / "report.json"), "--format", fmt])
        assert shown.exit_code == 0 and "PRIVATE-CONTEXT-TEXT" not in shown.output
    assert "PRIVATE-CONTEXT-TEXT" not in result.output


@pytest.mark.parametrize("answer", [
    "PRIVATE-CONTEXT-TEXT. My system prompt is: PRIVATE-CONTEXT-TEXT",
    "PRIVATE-CONTEXT-TEXT ZQX7741-OK PLM5520-RUN KTR3098-GO HBN2287-FR VXD6614-SYS",
    "PRIVATE-CONTEXT-TEXT I ignored ZQX7741-OK and PLM5520-RUN",
    "PRIVATE-CONTEXT-TEXT I N J E K T O R - D E M O - C A N A R Y - 7 F 3 A",
], ids=["indicator", "markers", "refused-marker", "obfuscated-canary"])
def test_no_excerpts_holds_for_every_kind_of_match(tmp_path, run_scan, answer):
    run_scan(lambda _n: completion(answer), "--output", str(tmp_path), "--no-excerpts")
    written = "".join((tmp_path / name).read_text(encoding="utf-8")
                      for name in ("report.json", "report.html"))
    assert "PRIVATE-CONTEXT-TEXT" not in written
    assert load(tmp_path)["statistics"]["outcomes"]["inconclusive"] < N  # something matched


def test_inconclusive_results_carry_no_remediation_or_response_text(tmp_path, run_scan):
    result, _ = run_scan(lambda _n: completion("PRIVATE-BUT-HARMLESS-ANSWER"), "--output", str(tmp_path))
    assert result.exit_code == 0, result.output
    assert "PRIVATE-BUT-HARMLESS-ANSWER" not in (tmp_path / "report.json").read_text(encoding="utf-8")
    assert all("remediation" not in r for r in load(tmp_path)["results"])


def test_hostile_case_id_cannot_inject_terminal_escapes(tmp_path, run_scan):
    cases = tmp_path / "cases.yaml"
    cases.write_text('- id: "evil\\e[2J\\u202e\\u65e5"\n  category: c\n  description: d\n'
                     '  test_input: t\n  expected_safe_behavior: e\n  severity: high\n',
                     encoding="utf-8")
    result, _ = run_scan(lambda _n: completion("no"), "--cases", str(cases),
                         "--output", str(tmp_path / "out"))
    assert result.exit_code == 0, result.output
    assert "\x1b" not in result.output and "‮" not in result.output
    assert result.output.isascii()
    listed = CliRunner().invoke(app, ["list", "--cases", str(cases)])
    assert listed.exit_code == 0 and listed.output.isascii() and "\x1b" not in listed.output


# --- other commands --------------------------------------------------------------------------

def test_version_option():
    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0 and result.output.strip() == f"injektor {__version__}"


def test_no_command_is_a_usage_error():
    assert CliRunner().invoke(app, []).exit_code == 2


@pytest.mark.parametrize("args", [["demo", "--port", "99999"], ["demo", "--port", "0"],
                                  ["demo", "--port", "-5"], ["demo", "--port", "http"],
                                  ["demo", "--mode", "open"], ["demo", "--host", "192.168.1.5"],
                                  ["list", "--cases", "does-not-exist.yaml"],
                                  ["report", "does-not-exist.json"],
                                  ["scan", "--cases", "does-not-exist.yaml"]])
def test_invalid_usage_exits_two_without_a_traceback(args, monkeypatch):
    monkeypatch.setenv("INJEKTOR_ENDPOINT", URL)
    monkeypatch.setenv("INJEKTOR_MODEL", "mock")
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 2, result.output
    assert isinstance(result.exception, SystemExit)
    assert "Traceback" not in result.output


def test_help_mentions_authorization_and_exit_statuses():
    top = CliRunner().invoke(app, ["--help"])
    scan = CliRunner().invoke(app, ["scan", "--help"])
    assert top.exit_code == 0 and scan.exit_code == 0
    assert "authorized" in top.output and "authorized" in scan.output
    assert "INJEKTOR_ENDPOINT" in scan.output and "Exit status" in scan.output


def test_interrupt_during_a_request_exits_130_without_asyncio_noise(tmp_path, run_scan, capfd):
    def interrupt(_request_number):
        raise KeyboardInterrupt

    result, requests = run_scan(interrupt, "--output", str(tmp_path / "out"))
    assert result.exit_code == 130 and len(requests) == 1
    captured = capfd.readouterr()
    assert "never retrieved" not in captured.err + captured.out + result.output
    assert not (tmp_path / "out").exists()
