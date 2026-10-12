"""Report content is untrusted: hostile, malformed and non-ASCII input must render safely."""
import json
import re

import pytest
from typer.testing import CliRunner

from injektor.cli import app
from injektor.reporting import LIMITATIONS, OUTCOMES, SCHEMA_VERSION, build_report, render_html, write_report

HOSTILE = [
    "<script>alert(1)</script>",
    "\"'><img src=x onerror=alert(1)>",
    "</td></tr></table><iframe src=javascript:alert(1)>",
    "</style><style>*{display:none}</style>",
    "</pre></details><a href='javascript:alert(1)'>x</a>",
    "<!-- --><svg/onload=alert(1)>",
    "&lt;already&gt; &amp; escaped",
    "' onmouseover='alert(1)",
    "\x00\x1b[2J‮ RTL \ud800 lone surrogate",
    "日本語 \U0001f512 éñ ☃",
]
FIELDS = ("test_id", "category", "severity", "outcome", "description", "expected_safe_behavior",
          "test_input", "remediation")


def hostile_result(value):
    result = {field: value for field in FIELDS}
    result.update(evidence=[value, value], excerpts=[value], response={value: value})
    return result


def tags(page):
    """Every tag name in the page, so that markup smuggled in by report content shows up."""
    return set(re.findall(r"<\s*/?\s*([a-zA-Z][a-zA-Z0-9]*)", page))


SAFE_TAGS = tags(render_html(build_report([hostile_result("plain text")], {"k": "v"})))


@pytest.mark.parametrize("value", HOSTILE)
def test_hostile_values_never_add_markup_or_attributes(value):
    report = build_report([hostile_result(value)], {"target": {"model": value, value: value}})
    page = render_html(report)
    assert tags(page) == SAFE_TAGS
    assert {"script", "img", "iframe", "svg", "a"}.isdisjoint(tags(page))
    assert page.count("<style>") == 1 and page.count("</style>") == 1
    assert not re.search(r"<[^>]*\son\w+\s*=", page)  # no event-handler attributes anywhere
    assert "javascript:" not in re.sub(r">[^<]*<", "><", page)  # none inside a tag


def test_outcome_from_the_report_never_becomes_a_class_name():
    page = render_html(build_report([hostile_result("x' onclick='alert(1)")]))
    assert "class='o-other'" in page
    assert set(re.findall(r"class='([^']*)'", page)) <= {
        "note", "tiles", "badge", "o-other", *(f"tile o-{name}" for name in OUTCOMES),
        *(f"o-{name}" for name in OUTCOMES)}


def test_page_forbids_scripts_and_network_requests():
    page = render_html(build_report([]))
    assert "Content-Security-Policy" in page and "default-src 'none'" in page
    # default-src does not cover these two; they stop a smuggled <base> or <form> from working.
    assert "base-uri 'none'" in page and "form-action 'none'" in page
    assert "<script" not in page and "http://" not in page and "https://" not in page


def test_page_explains_outcomes_limitations_and_shows_details():
    result = {"test_id": "case-1", "category": "indirect-injection", "severity": "high",
              "outcome": "confirmed", "evidence": ["Canary disclosed: X"], "excerpts": ["...X..."],
              "description": "What it does", "expected_safe_behavior": "Stay safe",
              "remediation": "Do the fix", "test_input": "line one\nline two"}
    page = render_html(build_report([result]))
    for expected in ("Heuristic indicators, not proof", "Do the fix", "Stay safe", "...X...",
                     "line one\nline two", "This is not a pass", *LIMITATIONS[:1]):
        assert expected.replace("'", "&#x27;") in page
    assert "<details class='o-confirmed' open>" in page


def test_json_report_carries_schema_definitions_and_limitations(tmp_path):
    jp, _ = write_report([], tmp_path)
    report = json.loads(jp.read_text(encoding="utf-8"))
    assert report["schema_version"] == SCHEMA_VERSION
    assert set(report["outcome_definitions"]) == {"confirmed", "potential", "inconclusive", "error"}
    assert report["limitations"] == list(LIMITATIONS)
    assert report["results"] == [] and report["statistics"]["total"] == 0


@pytest.mark.parametrize("value", HOSTILE)
def test_hostile_and_unicode_values_survive_a_json_round_trip(tmp_path, value):
    results = [hostile_result(value)]
    jp, hp = write_report(results, tmp_path)
    assert json.loads(jp.read_text(encoding="utf-8"))["results"] == results
    hp.read_text(encoding="utf-8")  # must be valid UTF-8 even with a lone surrogate inside


@pytest.mark.parametrize("results", [
    [{}], [{"outcome": "confirmed"}], [{"outcome": "confirmed", "evidence": "a bare string"}],
    [{"outcome": "potential", "evidence": [1, None, {"a": 1}], "excerpts": 5}],
    [{"outcome": "error", "evidence": None, "response": "not a mapping"}],
])
def test_incomplete_results_still_render(results):
    # As read back from a hand-edited file: no guarantee about any field.
    page = render_html({"results": results + ["not a mapping"], "statistics": "broken"})
    assert page.startswith("<!doctype html>") and page.endswith("</html>")


# --- `injektor report` on files it did not write ---------------------------------------------

def view(tmp_path, data, *args):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return CliRunner().invoke(app, ["report", str(path), *args])


def test_text_format_lists_each_case_with_evidence(tmp_path):
    report = build_report([{"test_id": "case-1", "category": "jailbreak", "severity": "high",
                            "outcome": "confirmed", "evidence": ["Canary disclosed: X"],
                            "excerpts": ["the X leaked"], "remediation": "Do the fix"}],
                          {"target": {"endpoint": "https://e.example/v1", "model": "m"},
                           "cases": {"file": "default.yaml", "sha256": "abc"}})
    result = view(tmp_path, report, "--format", "text")
    assert result.exit_code == 0, result.output
    for expected in ("Target: https://e.example/v1 (model m)", "Outcomes: 1 confirmed",
                     "confirmed    high     case-1 (jailbreak)", "evidence: Canary disclosed: X",
                     "excerpt: the X leaked", "remediation: Do the fix", "not proof"):
        assert expected in result.output


@pytest.mark.parametrize("value", HOSTILE)
def test_text_format_never_prints_control_characters_or_non_ascii(tmp_path, value):
    report = build_report([hostile_result(value)], {"target": {"endpoint": value, "model": value}})
    result = view(tmp_path, report, "--format", "text")
    assert result.exit_code == 0, result.output
    assert result.output.isascii()
    assert all(ch.isprintable() or ch == "\n" for ch in result.output)


@pytest.mark.parametrize("data", [
    {"statistics": {}}, {"statistics": {"outcomes": 5}, "results": "x", "provenance": []},
    {"statistics": {"outcomes": {"confirmed": "many"}}, "results": [1, None, {"evidence": 7}],
     "provenance": {"target": "x", "cases": None}},
])
@pytest.mark.parametrize("fmt", ["json", "text"])
def test_report_command_tolerates_hand_edited_files(tmp_path, data, fmt):
    result = view(tmp_path, data, "--format", fmt)
    assert result.exit_code == 0, result.output


def test_report_command_rejects_unknown_format_and_default_stays_json(tmp_path):
    assert view(tmp_path, {"statistics": {}}, "--format", "xml").exit_code == 2
    result = view(tmp_path, build_report([]))
    assert set(json.loads(result.stdout)) == {"generated_at", "statistics"}


# --- the outcome definitions agree between code, reports and README -----------------------------

def test_outcome_definitions_state_the_sentence_local_rule_everywhere():
    import re
    from pathlib import Path
    from injektor.reporting import OUTCOMES, render_html

    readme = Path(__file__).parents[1].joinpath("README.md").read_text(encoding="utf-8")
    table = {m.group(1): m.group(2) for m in re.finditer(r"^\| `(\w+)` \| (.*?) \|", readme, re.M)}
    assert set(OUTCOMES) <= set(table)
    for text in (OUTCOMES["confirmed"], table["confirmed"]):
        assert "sentence holding it" in text and "next to it" in text
    assert "next to" in OUTCOMES["potential"] and "next to" in table["potential"]
    assert "nothing else matched" in OUTCOMES["error"] and "nothing else matched" in table["error"]
    # The same definitions reach the HTML report and the JSON report through one dictionary.
    html_text = render_html({"results": [], "statistics": {"outcomes": {}}})
    assert "sentence holding it" in html_text
    assert "sentence before and after" in readme
