"""Safe JSON and HTML report generation."""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from .detection import score


def build_report(results: list[dict]) -> dict:
    return {"generated_at": datetime.now(timezone.utc).isoformat(),
            "statistics": score(results), "results": results}


def write_report(results: list[dict], output_dir: str | Path) -> tuple[Path, Path]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    report = build_report(results)
    json_path, html_path = out / "report.json", out / "report.html"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    rows = []
    for r in results:
        rows.append("<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in
            (r.get("test_id", ""), r.get("category", ""), r.get("severity", ""),
             r.get("outcome", ""), "; ".join(r.get("evidence", [])))) + "</tr>")
    document = "<!doctype html><meta charset='utf-8'><title>Injector security report</title>" \
        "<h1>Injector security report</h1><p>Heuristic indicators, not proof.</p>" \
        "<table><thead><tr><th>Test</th><th>Category</th><th>Severity</th><th>Outcome</th><th>Evidence</th></tr></thead><tbody>" \
        + "".join(rows) + "</tbody></table>"
    html_path.write_text(document, encoding="utf-8")
    return json_path, html_path
