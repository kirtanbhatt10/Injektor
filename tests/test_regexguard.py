"""Indicator regexes are untrusted: a catastrophic pattern must cost seconds, not hours."""
import json
import time
from functools import partial

import httpx
import pytest
from typer.testing import CliRunner

import injektor.cli as cli
import injektor.detection as detection
from injektor import config, regexguard
from injektor.cli import MAX_CONSECUTIVE_ERRORS, app
from injektor.config import AttackCase, load_cases
from injektor.detection import detect
from injektor.regexguard import find_spans
from injektor.target import OpenAICompatibleTarget

# Exponential backtracking: about 30 seconds at 26 characters and double for each one more.
CATASTROPHIC = r"(a+)+$"
BAIT = "a" * 60 + "!"
BASE = ("- id: {id}\n  category: c\n  description: d\n  test_input: {prompt}\n"
        "  expected_safe_behavior: e\n  severity: high\n  indicators: ['{pattern}']\n")


def make(indicators, canaries=(), test_input="please answer"):
    return AttackCase("x", "c", "d", test_input, "safe", "high", tuple(canaries), tuple(indicators))


def test_spans_match_in_process_results_and_skip_empty_matches():
    results, reason = find_spans([(r"b+", "abba Bb"), (r"x*", "abc"), (r"\bé\w+", "un été ÉTÉ")])
    assert reason == ""
    assert results == [[(1, 3), (5, 7)], [], [(3, 6), (7, 10)]]


def test_text_reaches_the_child_unchanged():
    text = "\ud800 lone \x00 nul \U0001f512 日本語 \r\n end"
    results, reason = find_spans([(r"end", text), (r"\U0001f512", text)])
    assert reason == "" and results == [[(text.index("end"), len(text))],
                                      [(text.index("\U0001f512"), text.index("\U0001f512") + 1)]]


def test_number_of_spans_is_bounded():
    results, _ = find_spans([(r"a", "a" * 5000)], limit=7)
    assert len(results[0]) == 7


def test_catastrophic_pattern_is_stopped_at_the_budget():
    started = time.monotonic()
    results, reason = find_spans([(r"safe", "a safe text"), (CATASTROPHIC, BAIT), (r"a", BAIT)],
                                 budget=3.0)
    assert time.monotonic() - started < 20
    # The finished job is kept; the one that ran out of time and the one after it are not run.
    assert results == [[(2, 6)], None, None]
    assert reason == "exceeded the 3-second time budget"


def test_child_is_dead_and_reaped_when_the_budget_runs_out(monkeypatch):
    started = []

    class Recording(regexguard.subprocess.Popen):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            started.append(self)

    monkeypatch.setattr(regexguard.subprocess, "Popen", Recording)
    results, _reason = find_spans([(CATASTROPHIC, BAIT)], budget=1.5)
    (child,) = started
    assert results == [None]
    assert child.returncode is not None and child.returncode != 0  # killed, and waited for
    assert child.stdout.closed and child.stdin.closed


def test_child_is_started_without_a_shell_and_without_case_content_in_its_arguments(monkeypatch):
    seen = {}
    real = regexguard.subprocess.run

    def spy(command, **kwargs):
        seen.update(command=command, kwargs=kwargs)
        return real(command, **kwargs)

    monkeypatch.setattr(regexguard.subprocess, "run", spy)
    pattern, text = r"PATTERN-ONLY-ON-STDIN", "TEXT-ONLY-ON-STDIN; $(touch x) & del x"
    assert find_spans([(pattern, text)]) == ([[]], "")
    assert seen["command"][0] == regexguard.sys.executable
    assert seen["command"][1:4] == ["-I", "-S", "-c"]  # isolated: no cwd, env or site imports
    assert "shell" not in seen["kwargs"]
    assert not any("ONLY-ON-STDIN" in part for part in seen["command"])
    assert b"ONLY-ON-STDIN" in seen["kwargs"]["input"]


def test_planted_module_in_the_working_directory_is_not_imported(tmp_path, monkeypatch):
    (tmp_path / "json.py").write_text("raise SystemExit('hijacked')\n", encoding="utf-8")
    (tmp_path / "re.py").write_text("raise SystemExit('hijacked')\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    assert find_spans([(r"b+", "abba")]) == ([[(1, 3)]], "")


def test_missing_interpreter_path_fails_closed(monkeypatch):
    monkeypatch.setattr(regexguard.sys, "executable", "")
    results, reason = find_spans([(r"a", "a")])
    assert results == [None] and "sys.executable is empty" in reason


def test_interpreter_that_cannot_be_started_fails_closed(monkeypatch):
    monkeypatch.setattr(regexguard.sys, "executable", "no-such-interpreter-for-injektor")
    results, reason = find_spans([(r"a", "a")])
    assert results == [None] and "could not be run" in reason


def test_no_jobs_start_no_process(monkeypatch):
    monkeypatch.setattr(regexguard.subprocess, "run", None)  # calling it would raise
    assert find_spans([]) == ([], "")
    assert detect(make([]), "anything")["outcome"] == "inconclusive"
    assert detect(make(["x"]), "")["outcome"] == "inconclusive"


def test_unevaluated_indicator_is_an_error_not_a_clean_result(monkeypatch):
    monkeypatch.setattr(detection, "find_spans", partial(find_spans, budget=2.0))
    result = detect(make([CATASTROPHIC]), BAIT)
    assert result["outcome"] == "error"
    assert result["evidence"][0] == ("1 of 1 indicator pattern(s) were not evaluated: "
                                     "evaluation exceeded the 2-second time budget.")
    assert result["excerpts"] == []


def test_finding_from_another_detector_survives_a_timeout(monkeypatch):
    monkeypatch.setattr(detection, "find_spans", partial(find_spans, budget=2.0))
    assert detect(make([CATASTROPHIC], ["SECRET-CANARY-1"]), "SECRET-CANARY-1 " + BAIT)[
        "outcome"] == "confirmed"
    result = detect(make([r"secret is", CATASTROPHIC]), "the secret is " + BAIT)
    assert result["outcome"] == "potential"


def test_case_file_whose_regex_hangs_on_its_own_prompt_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "LOAD_REGEX_BUDGET_SECONDS", 2.0)
    path = tmp_path / "cases.yaml"
    path.write_text(BASE.format(id="slow", prompt=BAIT, pattern=CATASTROPHIC), encoding="utf-8")
    with pytest.raises(ValueError, match="case slow could not be checked.*time budget"):
        load_cases(path)


def test_scan_with_a_hanging_regex_finishes_and_exits_three(tmp_path, monkeypatch):
    """The target answered every time, so the consecutive-error stop must not trigger."""
    cases = tmp_path / "cases.yaml"
    count = MAX_CONSECUTIVE_ERRORS + 2
    cases.write_text("".join(BASE.format(id=f"case-{n}", prompt="hello", pattern=CATASTROPHIC)
                             for n in range(count)), encoding="utf-8")
    load_cases(cases)  # the prompt check passes: the pattern is only slow on the answer
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": BAIT}}]})

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(cli, "OpenAICompatibleTarget",
                        lambda cfg: OpenAICompatibleTarget(cfg, transport=transport))
    monkeypatch.setattr(detection, "find_spans", partial(find_spans, budget=1.5))
    monkeypatch.setenv("INJEKTOR_ENDPOINT", "http://127.0.0.1:8765/v1/chat/completions")
    monkeypatch.setenv("INJEKTOR_MODEL", "mock-model")
    monkeypatch.delenv("INJEKTOR_DELAY", raising=False)
    output = tmp_path / "out"
    result = CliRunner().invoke(app, ["scan", "--cases", str(cases), "--output", str(output)])
    assert result.exit_code == 3, result.output
    assert len(requests) == count and "not sent" not in result.output
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert report["statistics"]["outcomes"]["error"] == count
    assert all("time budget" in r["evidence"][0] and "response" in r for r in report["results"])


# --- explicit input limits ------------------------------------------------------------------

def test_too_many_patterns_are_refused_not_truncated():
    jobs = [("a", "a")] * (regexguard.MAX_JOBS + 1)
    results, reason = find_spans(jobs)
    assert results == [None] * len(jobs) and "was refused" in reason and "5000" in reason


def test_oversized_payload_is_refused_before_a_child_is_started(monkeypatch):
    def no_child(*args, **kwargs):
        raise AssertionError("a child interpreter was started")
    monkeypatch.setattr(regexguard.subprocess, "run", no_child)
    text = "x" * (regexguard.MAX_PAYLOAD_BYTES + 1)
    results, reason = find_spans([("x", text)])
    assert results == [None] and "was refused" in reason and "bytes" in reason


def test_result_size_ceiling_is_checked_up_front(monkeypatch):
    monkeypatch.setattr(regexguard.subprocess, "run", lambda *a, **k: pytest.fail("child started"))
    results, reason = find_spans([("a", "a")], limit=10**9)
    assert results == [None] and "output limit" in reason


def test_limits_keep_a_full_case_file_check_and_a_full_scan_inside_the_ceilings():
    worst_output = (config.MAX_CASES * config.MAX_LIST_ITEMS
                    * (1 * regexguard.MAX_SPAN_BYTES + 1))
    assert config.MAX_CASES * config.MAX_LIST_ITEMS <= regexguard.MAX_JOBS
    assert worst_output < regexguard.MAX_PAYLOAD_BYTES
    assert config.MAX_LIST_ITEMS * 2 * (regexguard.MAX_SPANS_PER_PATTERN
                                        * regexguard.MAX_SPAN_BYTES + 1) < regexguard.MAX_PAYLOAD_BYTES


def test_case_file_is_read_only_up_to_its_limit(tmp_path, monkeypatch):
    big = tmp_path / "big.yaml"
    big.write_bytes(b"#" * (config.MAX_CASE_FILE_BYTES + 5))
    with pytest.raises(ValueError, match="larger than"):
        load_cases(big)
    # The bound is on the read itself, not only on a comparison afterwards.
    import builtins
    sizes = []
    real_open = builtins.open

    class Spy:
        def __init__(self, handle): self.handle = handle
        def __enter__(self):
            self.handle.__enter__()
            return self

        def __exit__(self, *a):
            return self.handle.__exit__(*a)

        def read(self, n=-1):
            sizes.append(n)
            return self.handle.read(n)
    monkeypatch.setattr(config, "open", lambda *a, **k: Spy(real_open(*a, **k)), raising=False)
    with pytest.raises(ValueError, match="larger than"):
        load_cases(big)
    assert sizes == [config.MAX_CASE_FILE_BYTES + 1]


def test_refused_regex_call_is_an_error_outcome_never_inconclusive(monkeypatch):
    monkeypatch.setattr(regexguard, "MAX_JOBS", 1)
    monkeypatch.setattr(detection, "find_spans", find_spans)
    result = detect(make(["one", "two"]), "an answer that matches nothing")
    assert result["outcome"] == "error"
    assert "were not evaluated" in result["evidence"][0] and "was refused" in result["evidence"][0]


# --- an incomplete regex check is stated next to any finding that was made ----------------------

MARK = "INJEKTOR-MARK-12345"


def test_potential_finding_states_that_a_regex_was_not_evaluated(monkeypatch):
    monkeypatch.setattr(detection, "find_spans", partial(find_spans, budget=1.5))
    result = detect(AttackCase("x", "c", "d", "please answer", "safe", "high", (),
                               (CATASTROPHIC, r"harmless pattern"), (MARK,)),
                    BAIT + f" I ignored {MARK}")
    assert result["outcome"] == "potential"
    incomplete = [line for line in result["evidence"] if "not evaluated" in line]
    assert incomplete == ["2 of 2 indicator pattern(s) were not evaluated: evaluation exceeded "
                          "the 1.5-second time budget."]
    assert result["evidence"][0].startswith("Marker ")  # the finding stays first
    assert not any("error" in line.lower() for line in result["evidence"])


def test_regex_potential_with_a_later_timeout_keeps_both_facts(monkeypatch):
    monkeypatch.setattr(detection, "find_spans", partial(find_spans, budget=1.5))
    result = detect(make([r"secret is", CATASTROPHIC]), "the secret is " + BAIT)
    assert result["outcome"] == "potential"
    assert any(line.startswith("Matched indicator pattern") for line in result["evidence"])
    assert sum("not evaluated" in line for line in result["evidence"]) == 1


def test_complete_evaluation_adds_no_incompleteness_note():
    result = detect(AttackCase("x", "c", "d", "please answer", "safe", "high", (), (r"fine\w*",),
                               (MARK,)), f"fine. I ignored {MARK}")
    assert result["outcome"] == "potential"
    assert not any("not evaluated" in line for line in result["evidence"])


def test_confirmed_finding_is_not_changed_by_a_regex_that_is_not_run(monkeypatch):
    monkeypatch.setattr(detection, "find_spans", lambda *a, **k: pytest.fail("regex was run"))
    case = AttackCase("x", "c", "d", "please answer", "safe", "high", (), (CATASTROPHIC,), (MARK,))
    assert detect(case, f"Output: {MARK}")["outcome"] == "confirmed"


@pytest.mark.parametrize("answer,status,outcome", [
    (BAIT + f" I ignored {MARK}", 0, "potential"),   # finding kept, regex unevaluated: no confirmed
    (BAIT + f" Output: {MARK}", 1, "confirmed"),
    (BAIT, 3, "error"),                                # nothing else matched
])
def test_exit_status_for_each_outcome_with_a_hanging_regex(tmp_path, monkeypatch, answer, status,
                                                           outcome):
    cases = tmp_path / "cases.yaml"
    cases.write_text(BASE.format(id="case-1", prompt="hello", pattern=CATASTROPHIC)
                     + f"  markers: ['{MARK}']\n", encoding="utf-8")
    transport = httpx.MockTransport(lambda request: httpx.Response(
        200, json={"choices": [{"message": {"content": answer}}]}))
    monkeypatch.setattr(cli, "OpenAICompatibleTarget",
                        lambda cfg: OpenAICompatibleTarget(cfg, transport=transport))
    monkeypatch.setattr(detection, "find_spans", partial(find_spans, budget=1.5))
    monkeypatch.setenv("INJEKTOR_ENDPOINT", "http://127.0.0.1:8765/v1/chat/completions")
    monkeypatch.setenv("INJEKTOR_MODEL", "mock-model")
    monkeypatch.delenv("INJEKTOR_DELAY", raising=False)
    output = tmp_path / "out"
    result = CliRunner().invoke(app, ["scan", "--cases", str(cases), "--output", str(output)])
    assert result.exit_code == status, result.output
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert report["results"][0]["outcome"] == outcome
    if outcome == "potential":
        assert any("not evaluated" in line for line in report["results"][0]["evidence"])
        # The same evidence reaches the HTML report and the text view of the JSON report.
        assert "not evaluated" in (output / "report.html").read_text(encoding="utf-8")
        shown = CliRunner().invoke(app, ["report", str(output / "report.json"), "--format", "text"])
        assert shown.exit_code == 0 and "not evaluated" in shown.output
        assert "sentence holding it" in json.dumps(report["outcome_definitions"])
