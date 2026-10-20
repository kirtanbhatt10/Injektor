"""CI-friendly views of a saved report: a Markdown summary and JUnit XML.

Both read the same dictionary as ``report.json``. The file may have been edited by hand,
so nothing is assumed about the shape of its optional parts.

What is left out on purpose: response excerpts (they can hold real content from the
target's hidden context) and the prompts that were sent. The Markdown summary is meant
for places many people can read, such as a GitHub Actions job summary, so it also leaves
out evidence lines, which name planted canaries. JUnit files are usually kept as build
artifacts and include the evidence, as report.json does.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from . import __version__

OUTCOME_ORDER = ("confirmed", "potential", "inconclusive", "error")
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_OUTCOME_RANK = {name: rank for rank, name in enumerate(OUTCOME_ORDER)}

# Characters XML 1.0 cannot carry at all, even escaped.
_XML_INVALID = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff\ud800-\udfff]")
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]<>()#+!|~])")


def _get(mapping: object, *keys: str) -> object:
    for key in keys:
        mapping = mapping.get(key) if isinstance(mapping, dict) else None
    return mapping


def _results(data: dict) -> list[dict]:
    results = data.get("results")
    return [r for r in results if isinstance(r, dict)] if isinstance(results, list) else []


def _strings(value: object) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [] if value in (None, "") else [str(value)]


def _outcomes(data: dict) -> dict[str, int]:
    """Counts per outcome, recomputed from the results when the statistics are unusable."""
    counts = _get(data, "statistics", "outcomes")
    if isinstance(counts, dict) and all(isinstance(counts.get(k, 0), int) for k in OUTCOME_ORDER):
        return {name: counts.get(name, 0) for name in OUTCOME_ORDER}
    out = dict.fromkeys(OUTCOME_ORDER, 0)
    for result in _results(data):
        if result.get("outcome") in out:
            out[result["outcome"]] += 1
    return out


# ------------------------------------------------------------------------------ Markdown


def _md(value: object, limit: int = 200) -> str:
    """One line of inert Markdown: no HTML, links, images, emphasis or table breaks."""
    text = " ".join(str(value).split())
    if len(text) > limit:
        text = text[:limit] + "..."
    text = "".join(ch if ch.isprintable() else " " for ch in text)
    return _MD_SPECIAL.sub(r"\\\1", text).replace("&", "&amp;")


def _sort_key(result: dict) -> tuple:
    return (_OUTCOME_RANK.get(result.get("outcome"), 9),
            _SEVERITY_RANK.get(str(result.get("severity", "")).lower(), 9),
            str(result.get("test_id", "")))


def to_markdown(data: dict) -> str:
    counts = _outcomes(data)
    target = _get(data, "provenance", "target")
    lines = ["## Injektor scan", ""]
    if isinstance(target, dict):
        lines.append(f"Target `{_md(target.get('endpoint', '?'), 120)}` "
                     f"(model `{_md(target.get('model', '?'), 80)}`)")
        lines.append("")
    if not any(counts.values()):
        verdict = "The report holds no results."
    elif counts["confirmed"]:
        verdict = f"**{counts['confirmed']} confirmed finding(s).** Read the evidence in report.html."
    elif counts["error"]:
        verdict = (f"**{counts['error']} case(s) could not be evaluated.** "
                   "Fix the cause and scan again.")
    elif counts["potential"]:
        verdict = f"**{counts['potential']} potential finding(s)** need a person to read the evidence."
    else:
        verdict = "No case matched. That is not a pass: the model may have complied in another way."
    lines += [verdict, "", "| Confirmed | Potential | Inconclusive | Error |", "|---|---|---|---|",
              "| " + " | ".join(str(counts[name]) for name in OUTCOME_ORDER) + " |", ""]
    results = sorted(_results(data), key=_sort_key)
    if results:
        lines += ["| Outcome | Severity | Case | Category |", "|---|---|---|---|"]
        for r in results:
            lines.append(f"| {_md(r.get('outcome', '?'), 20)} | {_md(r.get('severity', '?'), 20)} "
                         f"| {_md(r.get('test_id', '?'), 80)} | {_md(r.get('category', '?'), 60)} |")
        lines.append("")
    lines.append("_Heuristic indicators, not proof. Evidence and excerpts are kept out of this "
                 "summary; see report.json and report.html._")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------------- JUnit


def _xml(value: object, limit: int = 2000) -> str:
    text = _XML_INVALID.sub("?", str(value))
    return text if len(text) <= limit else text[:limit] + "..."


def to_junit(data: dict) -> str:
    """JUnit XML with one test case per Injektor case.

    confirmed -> failure, error -> error, potential and inconclusive -> skipped with the
    reason in the message. Neither of the last two is reported as passed: Injektor never
    treats "nothing matched" as a pass, and potential findings need a person to decide.
    """
    results = _results(data)
    counts = _outcomes({"results": results})
    duration = 0.0
    for r in results:
        seconds = _get(r, "response", "seconds")
        if isinstance(seconds, (int, float)) and not isinstance(seconds, bool):
            duration += float(seconds)
    suite = ET.Element("testsuite", {
        "name": "injektor",
        "tests": str(len(results)),
        "failures": str(counts["confirmed"]),
        "errors": str(counts["error"]),
        "skipped": str(counts["potential"] + counts["inconclusive"]),
        "time": f"{duration:.3f}",
        "timestamp": _xml(data.get("generated_at", ""), 64),
    })
    props = ET.SubElement(suite, "properties")
    for name, value in (("injektor.version", __version__),
                        ("target.endpoint", _get(data, "provenance", "target", "endpoint")),
                        ("target.model", _get(data, "provenance", "target", "model")),
                        ("cases.sha256", _get(data, "provenance", "cases", "sha256"))):
        if value not in (None, ""):
            ET.SubElement(props, "property", {"name": name, "value": _xml(value, 300)})
    for r in results:
        outcome = str(r.get("outcome", ""))
        seconds = _get(r, "response", "seconds")
        case = ET.SubElement(suite, "testcase", {
            "classname": f"injektor.{_xml(r.get('category', 'uncategorized'), 100)}",
            "name": _xml(r.get("test_id", "?"), 200),
            "time": f"{float(seconds):.3f}" if isinstance(seconds, (int, float))
                    and not isinstance(seconds, bool) else "0.000",
        })
        evidence = "\n".join(_xml(e, 1000) for e in _strings(r.get("evidence")))
        severity = _xml(r.get("severity", "?"), 20)
        if outcome == "confirmed":
            body = evidence
            if r.get("remediation"):
                body += f"\n\nRemediation: {_xml(r['remediation'])}"
            node = ET.SubElement(case, "failure", {
                "type": "confirmed", "message": f"Confirmed ({severity}): {_xml(r.get('description', ''), 300)}"})
            node.text = body
        elif outcome == "error":
            node = ET.SubElement(case, "error", {"type": "error",
                                                  "message": "The case could not be evaluated."})
            node.text = evidence
        elif outcome == "potential":
            ET.SubElement(case, "skipped", {
                "message": "potential: needs a person to read the evidence; not a pass"})
            ET.SubElement(case, "system-out").text = evidence
        else:
            ET.SubElement(case, "skipped", {
                "message": f"{_xml(outcome or 'unknown', 40)}: nothing matched; not a pass"})
    ET.indent(suite)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(suite, encoding="unicode") + "\n"
