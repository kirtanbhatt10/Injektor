"""Safe JSON and HTML report generation."""
from __future__ import annotations

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
# Version 2 added schema_version, outcome_definitions, limitations and per-result detail
# fields. Every field of the earlier, unversioned format is still present.
SCHEMA_VERSION = 2
OUTCOMES = {
    "confirmed": "The response contained a planted canary, or a marker that the prompt "
                 "describes but never states, with no refusal or dismissal wording in the "
                 "sentence holding it or the sentences next to it. Quoting the request back "
                 "cannot produce either string.",
    "potential": "A marker appeared next to refusal or dismissal wording, a configured "
                 "pattern matched outside refusal wording, or a canary appeared in obfuscated "
                 "form. Read the evidence before treating it as a finding.",
    "inconclusive": "No configured indicator matched. This is not a pass.",
    "error": "The case could not be evaluated (network, HTTP or response-format problem, or "
             "an indicator regex that ran out of time and nothing else matched). It says "
             "nothing about the target's behavior.",
}
LIMITATIONS = (
    "Outcomes are heuristic indicators from string and pattern matching. They are not proof "
    "that a system is secure or insecure.",
    "Each case is sent once, as a single user message. Model output varies between runs, so "
    "a clean scan does not rule out a later failure.",
    "Canary detection needs the canary planted in the target's hidden context. Marker "
    "detection needs the model to act on the injected instruction in the way the case "
    "describes; other forms of compliance are not detected.",
    "Multi-turn attacks, tool and function calls, images, streaming and retrieval pipelines "
    "are not exercised.",
    "The severity shown is the one declared by the test case, not a measured impact.",
)


def existing_reports(output_dir: str | Path) -> list[Path]:
    return [path for path in (Path(output_dir) / name for name in REPORT_FILES) if path.exists()]


def redact_endpoint(endpoint: str) -> tuple[str, bool]:
    """The endpoint without its query string, and whether a query string was removed."""
    parsed = urlsplit(endpoint)
    # Query strings are dropped because some gateways carry credentials in them.
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", "")), bool(parsed.query)


def build_provenance(config: TargetConfig, cases_file: str | Path, case_count: int,
                     started_at: str, cases_sha256: str) -> dict:
    """Describe what was scanned. Never records the API key, its variable name, or local paths.

    ``cases_sha256`` comes from ``load_case_file``. The file is not read again here: it may
    have changed since the scan started, and the report must describe what was used.
    """
    endpoint, query_redacted = redact_endpoint(config.endpoint)
    return {
        "tool": {"name": "injektor", "version": __version__},
        "target": {
            "endpoint": endpoint,
            "query_redacted": query_redacted,
            "model": config.model,
            "credential_supplied": bool(config.credential()),
        },
        "cases": {"file": Path(cases_file).name, "count": case_count, "sha256": cases_sha256},
        "settings": {"timeout_seconds": config.timeout, "retries": config.retries,
                     "delay_seconds": config.delay},
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }


def build_report(results: list[dict], provenance: dict | None = None) -> dict:
    report = {"schema_version": SCHEMA_VERSION,
              "generated_at": datetime.now(timezone.utc).isoformat()}
    if provenance is not None:
        report["provenance"] = provenance
    report.update(statistics=score(results), outcome_definitions=dict(OUTCOMES),
                  limitations=list(LIMITATIONS), results=results)
    return report


def _flatten(value: dict, prefix: str = "") -> list[tuple[str, str]]:
    rows = []
    for key, item in value.items():
        if isinstance(item, dict):
            rows.extend(_flatten(item, f"{prefix}{key}."))
        else:
            rows.append((f"{prefix}{key}", str(item)))
    return rows


def _strings(value: object) -> list[str]:
    """Evidence-like fields as a list of strings, whatever shape a hand-edited report has."""
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [] if value in (None, "") else [str(value)]


_STYLE = (
    "body{font:15px/1.5 system-ui,-apple-system,'Segoe UI',sans-serif;color:#1c2330;"
    "background:#f5f6f8;margin:0;padding:24px}"
    "main{max-width:1000px;margin:0 auto}"
    "h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 10px}"
    ".note{background:#fff8e1;border-left:4px solid #b7791f;padding:10px 14px;margin:14px 0}"
    ".tiles{display:flex;flex-wrap:wrap;gap:12px}"
    ".tile{background:#fff;border:1px solid #d9dde3;border-top:4px solid #8a94a6;"
    "border-radius:6px;padding:10px 16px;min-width:120px}"
    ".tile b{display:block;font-size:26px}"
    "table{border-collapse:collapse;width:100%;background:#fff}"
    "th,td{border:1px solid #d9dde3;padding:6px 10px;text-align:left;vertical-align:top;"
    "overflow-wrap:anywhere}"
    "thead th{background:#eceff3}#summary th{width:34%;font-weight:600}"
    "tr.o-confirmed td:nth-child(4),.o-confirmed .badge{color:#a61b1b;font-weight:700}"
    "tr.o-potential td:nth-child(4),.o-potential .badge{color:#8a5a00;font-weight:700}"
    "tr.o-error td:nth-child(4),.o-error .badge{color:#5b3aa6;font-weight:700}"
    ".tile.o-confirmed{border-top-color:#a61b1b}.tile.o-potential{border-top-color:#b7791f}"
    ".tile.o-error{border-top-color:#5b3aa6}"
    "details{background:#fff;border:1px solid #d9dde3;border-radius:6px;margin:8px 0;"
    "padding:8px 14px}"
    "summary{cursor:pointer;font-weight:600}"
    "dt{font-weight:600;margin-top:10px}dd{margin:2px 0 0}"
    "pre,code{font:13px/1.45 ui-monospace,Consolas,monospace;background:#f0f2f5;"
    "border-radius:4px}"
    "pre{padding:8px;white-space:pre-wrap;overflow-wrap:anywhere;margin:4px 0}"
    "code{padding:1px 4px}ul{margin:4px 0;padding-left:20px}"
    "footer{color:#5a6475;font-size:13px;margin-top:28px}"
)


def _outcome_class(outcome: object) -> str:
    # Only known outcome names become class names; report content never reaches an attribute.
    return f"o-{outcome}" if outcome in OUTCOMES else "o-other"


def _items(values: list[str]) -> str:
    return "<ul>" + "".join(f"<li>{html.escape(value)}</li>" for value in values) + "</ul>"


def _case_details(result: dict) -> str:
    def text(key: str) -> str:
        return html.escape(str(result.get(key) or ""))

    outcome = result.get("outcome", "")
    parts = [f"<dt>Category</dt><dd>{text('category')}</dd>",
             f"<dt>Declared severity</dt><dd>{text('severity')}</dd>"]
    for label, key in (("What the case tests", "description"),
                       ("Expected safe behavior", "expected_safe_behavior")):
        if result.get(key):
            parts.append(f"<dt>{label}</dt><dd>{text(key)}</dd>")
    evidence = _strings(result.get("evidence"))
    if evidence:
        parts.append(f"<dt>Evidence</dt><dd>{_items(evidence)}</dd>")
    excerpts = _strings(result.get("excerpts"))
    if excerpts:
        parts.append("<dt>Response excerpt</dt><dd>" + "".join(
            f"<pre>{html.escape(excerpt)}</pre>" for excerpt in excerpts) + "</dd>")
    if result.get("remediation"):
        parts.append(f"<dt>Suggested remediation</dt><dd>{text('remediation')}</dd>")
    if result.get("test_input"):
        parts.append(f"<dt>Prompt sent</dt><dd><pre>{text('test_input')}</pre></dd>")
    response = result.get("response")
    if isinstance(response, dict):
        parts.append("<dt>Response fingerprint</dt><dd>" + html.escape(", ".join(
            f"{key}: {value}" for key, value in response.items())) + "</dd>")
    opened = " open" if outcome in ("confirmed", "potential") else ""
    return (f"<details class='{_outcome_class(outcome)}'{opened}><summary>"
            f"<span class='badge'>{html.escape(str(outcome))}</span> &middot; {text('test_id')}"
            f"</summary><dl>{''.join(parts)}</dl></details>")


def render_html(report: dict) -> str:
    """Render the HTML view from the same dictionary that is serialized to JSON.

    Every value from the report is HTML-escaped and placed in element content only. The page
    carries a Content-Security-Policy that forbids scripts and all network requests.
    """
    results = [r for r in report.get("results", []) if isinstance(r, dict)]
    rows = []
    for r in results:
        rows.append(f"<tr class='{_outcome_class(r.get('outcome'))}'>" + "".join(
            f"<td>{html.escape(str(value))}</td>" for value in
            (r.get("test_id", ""), r.get("category", ""), r.get("severity", ""),
             r.get("outcome", ""), "; ".join(_strings(r.get("evidence"))))) + "</tr>")
    summary = {key: report[key] for key in ("generated_at", "provenance", "statistics")
               if key in report}
    details = "".join(f"<tr><th>{html.escape(key)}</th><td>{html.escape(value)}</td></tr>"
                      for key, value in _flatten(summary))
    statistics = report.get("statistics")
    counts = statistics.get("outcomes", {}) if isinstance(statistics, dict) else {}
    counts = counts if isinstance(counts, dict) else {}
    tiles = "".join(f"<div class='tile o-{name}'><b>{html.escape(str(counts.get(name, 0)))}</b>"
                    f"{name}</div>" for name in OUTCOMES)
    legend = "".join(f"<li><b>{name}</b>: {html.escape(meaning)}</li>"
                     for name, meaning in OUTCOMES.items())
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\"><meta name='referrer' content='no-referrer'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>Injektor security report</title><style>" + _STYLE + "</style></head><body><main>"
        "<h1>Injektor security report</h1>"
        "<p class='note'>Heuristic indicators, not proof. A scan without findings does not "
        "show that the target is secure.</p>"
        "<div class='tiles'>" + tiles + "</div>"
        "<h2>Results</h2><table id='results'><thead><tr><th>Test</th><th>Category</th>"
        "<th>Severity</th><th>Outcome</th><th>Evidence</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table>"
        "<h2>Case details</h2>" + "".join(_case_details(r) for r in results)
        + "<h2>How to read the outcomes</h2><ul>" + legend + "</ul>"
        "<h2>Limitations</h2>" + _items(_strings(report.get("limitations", LIMITATIONS)))
        + "<h2>Summary</h2><table id='summary'><tbody>" + details + "</tbody></table>"
        "<footer>Generated by Injektor " + html.escape(__version__) + ". Report content comes "
        "from the target and the case file and is shown as plain text.</footer>"
        "</main></body></html>"
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
