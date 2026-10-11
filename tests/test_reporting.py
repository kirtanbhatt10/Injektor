import json

from injector.reporting import write_report


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
    assert page.count("&lt;img src=x onerror=alert(1)&gt;") == 6


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
