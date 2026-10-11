import json

from injector.reporting import write_report


def test_reports_escape_untrusted_html(tmp_path):
    xss = "<script>alert(1)</script>"
    jp, hp = write_report([{"test_id": xss, "category": "x", "severity": "high",
                            "outcome": "potential", "evidence": [xss]}], tmp_path)
    assert json.loads(jp.read_text(encoding="utf-8"))["results"][0]["test_id"] == xss
    assert "<script>alert(1)</script>" not in hp.read_text(encoding="utf-8")
    assert "&lt;script&gt;" in hp.read_text(encoding="utf-8")
