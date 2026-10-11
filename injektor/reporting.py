"""Safe JSON and HTML report generation."""
from __future__ import annotations

import hashlib
import html
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from . import __version__
from .config import TargetConfig
from .detection import score

REPORT_FILES = ("report.json", "report.html")


def existing_reports(output_dir: str | Path) -> list[Path]:
    return [path for path in (Path(output_dir) / name for name in REPORT_FILES) if path.exists()]


def build_provenance(config: TargetConfig, cases_file: str | Path, case_count: int,
                     started_at: str) -> dict:
    """Describe what was scanned. Never records the API key, its variable name, or local paths."""
    parsed = urlsplit(config.endpoint)
    cases_path = Path(cases_file)
    return {
        "tool": {"name": "injektor", "version": __version__},
        "target": {
            # Query strings are dropped because some gateways carry credentials in them.
            "endpoint": urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", "")),
            "query_redacted": bool(parsed.query),
            "model": config.model,
            "credential_supplied": bool(config.credential()),
        },
        "cases": {"file": cases_path.name, "count": case_count,
                  "sha256": hashlib.sha256(cases_path.read_bytes()).hexdigest()},
        "settings": {"timeout_seconds": config.timeout, "retries": config.retries},
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }


def build_report(results: list[dict], provenance: dict | None = None) -> dict:
    report = {"generated_at": datetime.now(timezone.utc).isoformat()}
    if provenance is not None:
        report["provenance"] = provenance
    report.update(statistics=score(results), results=results)
    return report


def _flatten(value: dict, prefix: str = "") -> list[tuple[str, str]]:
    rows = []
    for key, item in value.items():
        if isinstance(item, dict):
            rows.extend(_flatten(item, f"{prefix}{key}."))
        else:
            rows.append((f"{prefix}{key}", str(item)))
    return rows


def render_html(report: dict) -> str:
    """Render the HTML view from the same dictionary that is serialized to JSON."""
    rows = []
    for r in report["results"]:
        rows.append("<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in
            (r.get("test_id", ""), r.get("category", ""), r.get("severity", ""),
             r.get("outcome", ""), "; ".join(r.get("evidence", [])))) + "</tr>")
    summary = {key: report[key] for key in ("generated_at", "provenance", "statistics")
               if key in report}
    details = "".join(f"<tr><th>{html.escape(key)}</th><td>{html.escape(value)}</td></tr>"
                      for key, value in _flatten(summary))
    return (
        "<!doctype html><meta charset='utf-8'><title>Injektor security report</title>"
        "<h1>Injektor security report</h1><p>Heuristic indicators, not proof.</p>"
        "<h2>Summary</h2><table id='summary'><tbody>" + details + "</tbody></table>"
        "<h2>Results</h2><table id='results'><thead><tr><th>Test</th><th>Category</th>"
        "<th>Severity</th><th>Outcome</th><th>Evidence</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table>"
    )


def _stage(directory: Path, content: str) -> Path:
    """Write content to a temporary file next to its destination and flush it to disk."""
    descriptor, name = tempfile.mkstemp(dir=directory, prefix=".report-", suffix=".tmp")
    try:
        # Lone surrogates (possible through YAML escapes) cannot be encoded as UTF-8. They are
        # written as backslash escapes, which JSON readers turn back into the original text.
        with os.fdopen(descriptor, "w", encoding="utf-8", errors="backslashreplace") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        _remove(Path(name))
        raise
    return Path(name)


def _remove(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


def write_report(results: list[dict], output_dir: str | Path, provenance: dict | None = None,
                 overwrite: bool = False) -> tuple[Path, Path]:
    """Write report.json and report.html as a pair.

    Both documents are rendered and staged in temporary files before either destination is
    touched. If publishing fails part-way, the directory is returned to its previous state:
    new files are removed and replaced files are restored.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path, html_path = (out / name for name in REPORT_FILES)
    existing = existing_reports(out)
    if existing and not overwrite:
        raise FileExistsError(f"Refusing to overwrite existing report: {existing[0]}")
    report = build_report(results, provenance)
    contents = ((json_path, json.dumps(report, indent=2, ensure_ascii=False)),
                (html_path, render_html(report)))
    staged: list[tuple[Path, Path]] = []
    created: list[Path] = []
    backups: list[tuple[Path, Path]] = []
    try:
        for final, content in contents:
            staged.append((_stage(out, content), final))
        for temporary, final in staged:
            if overwrite:
                if final.exists():
                    descriptor, name = tempfile.mkstemp(dir=out, prefix=".report-", suffix=".bak")
                    os.close(descriptor)
                    try:
                        os.replace(final, name)
                    except BaseException:
                        _remove(Path(name))
                        raise
                    backups.append((Path(name), final))
            else:
                # Exclusive creation claims the name atomically, so a report written by a
                # concurrent scan after the check above is never replaced.
                with open(final, "x", encoding="utf-8"):
                    pass
            created.append(final)
            os.replace(temporary, final)
    except BaseException:
        for final in created:
            _remove(final)
        for backup, final in backups:
            try:
                os.replace(backup, final)
            except OSError:
                pass  # the previous content stays in the .bak file; keep restoring the rest
        raise
    finally:
        for temporary, _final in staged:
            _remove(temporary)
    for backup, _final in backups:
        _remove(backup)
    return json_path, html_path
