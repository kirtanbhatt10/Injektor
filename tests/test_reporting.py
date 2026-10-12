import html
import json
import os
import re
from pathlib import Path

import pytest

import injektor.reporting as reporting
from injektor.config import TargetConfig
from injektor.reporting import build_provenance, write_report

CASES = Path(reporting.__file__).parent / "cases" / "default.yaml"
RESULTS = [
    {"test_id": "a", "category": "direct", "severity": "high", "timestamp": "t1",
     "outcome": "confirmed", "evidence": ["Canary disclosed: X", "second <b>item</b>"]},
    {"test_id": "b", "category": "leak", "severity": "low", "timestamp": "t2",
     "outcome": "error", "evidence": ["Target returned HTTP 500."]},
]
OLD = {"report.json": b'{"old": "json"}\r\n', "report.html": b"<p>old html</p>\n"}


def provenance():
    config = TargetConfig("https://gateway.example.com/v1/chat?key=QUERY-SECRET", "model-x")
    return build_provenance(config, CASES, 4, "2026-01-01T00:00:00+00:00", "ab" * 32)


def snapshot(directory):
    return {path.name: path.read_bytes() for path in directory.iterdir()}


def table(page, table_id):
    """Return the unescaped cell text of every row in one of the report's tables."""
    body = re.search(rf"<table id='{table_id}'>.*?<tbody>(.*?)</tbody>", page, re.S).group(1)
    return [[html.unescape(cell) for cell in re.findall(r"<t[dh]>(.*?)</t[dh]>", row, re.S)]
            for row in re.findall(r"<tr[^>]*>(.*?)</tr>", body, re.S)]


def fail_on_call(monkeypatch, name, number):
    """Make the nth call to an os function used by the report writer raise OSError."""
    real, calls = getattr(os, name), []

    def flaky(*args, **kwargs):
        calls.append(args)
        if len(calls) == number:
            raise OSError("simulated disk failure")
        return real(*args, **kwargs)

    monkeypatch.setattr(reporting.os, name, flaky)


def test_reports_escape_untrusted_html(tmp_path):
    xss = "<script>alert(1)</script>"
    jp, hp = write_report([{"test_id": xss, "category": "x", "severity": "high",
                            "outcome": "potential", "evidence": [xss]}], tmp_path)
    assert json.loads(jp.read_text(encoding="utf-8"))["results"][0]["test_id"] == xss
    assert "<script>alert(1)</script>" not in hp.read_text(encoding="utf-8")
    assert "&lt;script&gt;" in hp.read_text(encoding="utf-8")


def test_html_escapes_every_field_and_attribute_breakers(tmp_path):
    hostile = "\"'><img src=x onerror=alert(1)>&"
    _, hp = write_report([{"test_id": hostile, "category": hostile, "severity": hostile,
                           "outcome": hostile, "evidence": [hostile, hostile]}], tmp_path)
    page = hp.read_text(encoding="utf-8")
    assert "<img" not in page
    assert "onerror=alert(1)>" not in page
    # results table: four cells and two evidence items; summary table: the outcome name;
    # case details: badge, test id, category, severity and two evidence items
    assert page.count("&lt;img src=x onerror=alert(1)&gt;") == 13


def test_json_report_roundtrips_and_statistics_match_results(tmp_path):
    results = [{"test_id": "a", "category": "c", "severity": "high", "outcome": outcome,
                "evidence": ["snowman ☃ </script>"]}
               for outcome in ("confirmed", "potential", "inconclusive", "error")]
    jp, _ = write_report(results, tmp_path)
    report = json.loads(jp.read_text(encoding="utf-8"))
    assert report["results"] == results
    assert report["statistics"] == {
        "total": 4, "indicator_score": 3,
        "outcomes": {"confirmed": 1, "potential": 1, "inconclusive": 1, "error": 1}}


def test_json_and_html_carry_the_same_provenance_and_results(tmp_path):
    supplied = provenance()
    jp, hp = write_report(RESULTS, tmp_path, supplied)
    report = json.loads(jp.read_text(encoding="utf-8"))
    page = hp.read_text(encoding="utf-8")
    assert report["provenance"] == supplied
    assert report["results"] == RESULTS
    summary = dict(table(page, "summary"))
    expected = dict(reporting._flatten({key: report[key] for key in
                                        ("generated_at", "provenance", "statistics")}))
    assert summary == expected
    assert summary["generated_at"] == report["generated_at"]
    assert summary["provenance.target.endpoint"] == "https://gateway.example.com/v1/chat"
    assert summary["statistics.outcomes.confirmed"] == "1"
    assert table(page, "results") == [
        [r["test_id"], r["category"], r["severity"], r["outcome"], "; ".join(r["evidence"])]
        for r in report["results"]]
    assert "QUERY-SECRET" not in page + jp.read_text(encoding="utf-8")


def test_report_without_provenance_omits_it_from_both_files(tmp_path):
    jp, hp = write_report(RESULTS, tmp_path)
    assert "provenance" not in json.loads(jp.read_text(encoding="utf-8"))
    summary = table(hp.read_text(encoding="utf-8"), "summary")
    assert not any(key.startswith("provenance") for key, _ in summary)


@pytest.mark.parametrize("present", [("report.json",), ("report.html",),
                                     ("report.json", "report.html")])
def test_existing_reports_are_untouched_without_overwrite(tmp_path, present):
    for name in present:
        (tmp_path / name).write_bytes(OLD[name])
    before = snapshot(tmp_path)
    with pytest.raises(FileExistsError):
        write_report(RESULTS, tmp_path, provenance())
    assert snapshot(tmp_path) == before  # same bytes, no new file, no temporary file


def test_overwrite_replaces_both_files_and_leaves_no_temporaries(tmp_path):
    for name, content in OLD.items():
        (tmp_path / name).write_bytes(content)
    jp, hp = write_report(RESULTS, tmp_path, provenance(), overwrite=True)
    assert sorted(snapshot(tmp_path)) == ["report.html", "report.json"]
    assert json.loads(jp.read_text(encoding="utf-8"))["results"] == RESULTS
    assert "old html" not in hp.read_text(encoding="utf-8")


def test_overwrite_with_only_one_previous_file_writes_a_matching_pair(tmp_path):
    (tmp_path / "report.html").write_bytes(OLD["report.html"])
    jp, hp = write_report(RESULTS, tmp_path, provenance(), overwrite=True)
    report = json.loads(jp.read_text(encoding="utf-8"))
    summary = dict(table(hp.read_text(encoding="utf-8"), "summary"))
    assert summary["generated_at"] == report["generated_at"]
    assert sorted(snapshot(tmp_path)) == ["report.html", "report.json"]


# Without overwrite, os.replace runs once per published file.
@pytest.mark.parametrize("failing_call", [1, 2])
def test_failed_publish_leaves_no_partial_report(tmp_path, monkeypatch, failing_call):
    fail_on_call(monkeypatch, "replace", failing_call)
    with pytest.raises(OSError, match="simulated"):
        write_report(RESULTS, tmp_path, provenance())
    assert snapshot(tmp_path) == {}


# With overwrite, each file needs a backup rename and then a publishing rename.
@pytest.mark.parametrize("failing_call", [1, 2, 3, 4])
def test_failed_overwrite_restores_the_previous_pair(tmp_path, monkeypatch, failing_call):
    for name, content in OLD.items():
        (tmp_path / name).write_bytes(content)
    fail_on_call(monkeypatch, "replace", failing_call)
    with pytest.raises(OSError, match="simulated"):
        write_report(RESULTS, tmp_path, provenance(), overwrite=True)
    assert snapshot(tmp_path) == OLD


@pytest.mark.parametrize("overwrite", [False, True])
@pytest.mark.parametrize("failing_call", [1, 2])
def test_failure_while_staging_changes_nothing(tmp_path, monkeypatch, overwrite, failing_call):
    if overwrite:
        for name, content in OLD.items():
            (tmp_path / name).write_bytes(content)
    before = snapshot(tmp_path)
    fail_on_call(monkeypatch, "fsync", failing_call)
    with pytest.raises(OSError, match="simulated"):
        write_report(RESULTS, tmp_path, provenance(), overwrite=overwrite)
    assert snapshot(tmp_path) == before


def test_report_created_by_a_concurrent_scan_is_not_replaced(tmp_path, monkeypatch):
    """A report appears after the up-front check but before this one is published."""
    real_stage, staged = reporting._stage, []

    def stage_then_race(directory, content):
        path = real_stage(directory, content)
        staged.append(path)
        if len(staged) == 2:
            (tmp_path / "report.html").write_bytes(OLD["report.html"])
        return path

    monkeypatch.setattr(reporting, "_stage", stage_then_race)
    with pytest.raises(FileExistsError):
        write_report(RESULTS, tmp_path, provenance())
    assert snapshot(tmp_path) == {"report.html": OLD["report.html"]}
