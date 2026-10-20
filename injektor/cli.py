"""Typer CLI for listing cases, scanning, reporting, and local demo."""
from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import typer

from . import __version__
from .ci_formats import to_junit, to_markdown
from .config import AttackCase, TargetConfig, load_case_file, load_cases
from .detection import detect, score
from .reporting import build_provenance, existing_reports, redact_endpoint, write_report
from .target import (MAX_CONTENT_CHARS, AuthenticationRejected, OpenAICompatibleTarget,
                     TargetError)

# Locals are never rendered in tracebacks: request frames hold the Authorization header.
app = typer.Typer(help="Evaluate prompt-injection indicators against an authorized LLM endpoint.",
                  pretty_exceptions_show_locals=False)
CASES = Path(__file__).resolve().parent / "cases" / "default.yaml"
# 2 is reserved by the CLI framework for invalid usage and configuration.
EXIT_CONFIRMED, EXIT_OPERATIONAL_ERROR, EXIT_INTERRUPTED = 1, 3, 130
# A target that keeps failing is left alone: repeating a rejected credential can lock an
# account, and repeating requests against an overloaded service makes the overload worse.
MAX_CONSECUTIVE_ERRORS = 3
DEFAULT_REMEDIATION = ("Review the evidence and the full response by hand. If the behavior is "
                       "confirmed, add controls outside the model: input and output filtering, "
                       "least-privilege tool access, and separation of untrusted content.")


def _plain(value: object, limit: int = 300) -> str:
    """Text that is safe to print: no control or escape sequences, and ASCII only so that it
    survives legacy Windows console code pages."""
    text = "".join(ch if ch.isprintable() else " " for ch in str(value))
    text = text.encode("ascii", "backslashreplace").decode("ascii")
    return text if len(text) <= limit else text[:limit] + "..."


def _version(value: bool) -> None:
    if value:
        typer.echo(f"injektor {__version__}")
        raise typer.Exit()


@app.callback()
def main(version: bool = typer.Option(False, "--version", callback=_version, is_eager=True,
                                      help="Show the version and exit.")):
    """Evaluate prompt-injection indicators against an authorized LLM endpoint.

    Only test systems you own or are explicitly authorized to assess. Outcomes are heuristic
    indicators, not proof that a system is secure or insecure.
    """


@app.command("list")
def list_cases(cases_file: Path = typer.Option(CASES, "--cases", help="YAML case file")):
    """List the test cases (the built-in suite unless --cases is given)."""
    try:
        cases = load_cases(cases_file)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    for case in cases:
        typer.echo(_plain(f"{case.id:28} {case.severity:8} {case.category} - {case.description}"))


@app.command()
def scan(output: Path = typer.Option(Path("reports"), "--output", help="Report output directory"),
         cases_file: Path = typer.Option(CASES, "--cases", help="YAML case file"),
         overwrite: bool = typer.Option(False, "--overwrite",
                                        help="Replace an existing report in the output directory"),
         no_excerpts: bool = typer.Option(False, "--no-excerpts",
                                          help="Do not store response excerpts in the report")):
    """Run the bounded test suite against explicitly configured target variables.

    The target is read from INJEKTOR_ENDPOINT and INJEKTOR_MODEL. One request is sent per
    case, one at a time. Only scan systems you are authorized to assess.

    Exit status: 0 no confirmed finding, 1 confirmed finding, 2 invalid usage or
    configuration, 3 operational error (a case could not be evaluated, the report could
    not be written, or the scan failed unexpectedly). A confirmed finding takes precedence
    over operational errors.
    """
    try:
        config = TargetConfig.from_env()
        cases, cases_sha256 = load_case_file(cases_file)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    # Checked before any request is sent, so a refused overwrite costs the target nothing.
    existing = existing_reports(output)
    if existing and not overwrite:
        raise typer.BadParameter(f"{existing[0]} already exists. Choose another --output "
                                 "directory or pass --overwrite.")
    # The output directory may not exist yet; whatever does exist on the way to it must be a
    # directory, or the report could not be written after the whole scan had run.
    for path in (output, *output.parents):
        if path.exists():
            if not path.is_dir():
                raise typer.BadParameter(f"{path} exists and is not a directory, so no report "
                                         f"can be written to {output}.")
            break
    try:
        status = _run_scan(config, cases, cases_file, cases_sha256, output, overwrite,
                           not no_excerpts)
    except KeyboardInterrupt:
        # Stated here rather than left to the CLI framework, whose handling of an interrupt
        # has differed between versions (status 1 would read as a confirmed finding).
        typer.echo("Scan interrupted. No report was written.", err=True)
        raise typer.Exit(EXIT_INTERRUPTED) from None
    except Exception as exc:
        # Python would exit with status 1 here, which is reserved for confirmed findings.
        # Only the type is shown: exception messages can embed request data.
        typer.echo(f"Scan aborted by an unexpected internal error ({type(exc).__name__}).", err=True)
        status = EXIT_OPERATIONAL_ERROR
    if status:
        raise typer.Exit(status)


def _evaluate(case: AttackCase, target: OpenAICompatibleTarget, keep_excerpts: bool) -> dict:
    started = time.monotonic()
    response = target.ask(case.test_input)
    seconds = round(time.monotonic() - started, 3)
    result = detect(case, response)
    if not keep_excerpts:
        result.pop("excerpts", None)
    if target.last_response_truncated:
        result["evidence"].append(f"The answer was longer than {MAX_CONTENT_CHARS} characters; "
                                  "only the first part was examined.")
    # A fingerprint instead of the full text: enough to tell whether two runs got the same
    # answer without storing everything the target said. Length and hash describe the text
    # that was examined, which is the truncated text when "truncated" is true.
    result["response"] = {
        "characters": len(response),
        "sha256": hashlib.sha256(response.encode("utf-8", "backslashreplace")).hexdigest(),
        "truncated": target.last_response_truncated,
        "seconds": seconds,
    }
    if result["outcome"] in ("confirmed", "potential"):
        result["remediation"] = case.remediation or DEFAULT_REMEDIATION
    return result


def _run_scan(config: TargetConfig, cases: list[AttackCase], cases_file: Path, cases_sha256: str,
              output: Path, overwrite: bool, keep_excerpts: bool = True) -> int:
    target = OpenAICompatibleTarget(config)
    try:
        return _scan_and_report(target, config, cases, cases_file, cases_sha256, output,
                                overwrite, keep_excerpts)
    finally:
        target.close()


def _scan_and_report(target: OpenAICompatibleTarget, config: TargetConfig,
                     cases: list[AttackCase], cases_file: Path, cases_sha256: str, output: Path,
                     overwrite: bool, keep_excerpts: bool) -> int:
    scan_started = datetime.now(timezone.utc).isoformat()
    typer.echo(f"Target: {_plain(redact_endpoint(config.endpoint)[0])} (model "
               f"{_plain(config.model, 80)}). Sending up to {len(cases)} requests, one at a "
               "time. Only scan systems you are authorized to assess.", err=True)
    results = []
    consecutive_errors = 0
    stopped = ""  # why no further request is sent, once that has been decided
    for number, case in enumerate(cases, 1):
        started = datetime.now(timezone.utc).isoformat()
        shown = ""
        if stopped:
            shown = " (not sent)"
            result = {"outcome": "error", "evidence": [f"Not sent: {stopped}"]}
        else:
            if config.delay and number > 1:
                time.sleep(config.delay)
            try:
                result = _evaluate(case, target, keep_excerpts)
                # The target replied, whatever the detector made of the answer.
                consecutive_errors = 0
            except TargetError as exc:
                result = {"outcome": "error", "evidence": [str(exc)]}
                consecutive_errors += 1
                if isinstance(exc, AuthenticationRejected):
                    stopped = ("the target rejected the request (HTTP 401 or 403), so the "
                               "credential is not sent again.")
                elif consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                    stopped = ("the scan stopped contacting the target after "
                               f"{MAX_CONSECUTIVE_ERRORS} consecutive errors.")
        typer.echo(f"[{number}/{len(cases)}] {_plain(case.id, 60):28} {result['outcome']}{shown}")
        results.append({"test_id": case.id, "category": case.category,
                        "severity": case.severity, "timestamp": started,
                        "description": case.description,
                        "expected_safe_behavior": case.expected_safe_behavior,
                        "test_input": case.test_input, **result})
    outcomes = score(results)["outcomes"]
    summary = f"{len(results)} cases: " + ", ".join(f"{n} {name}" for name, n in outcomes.items())
    try:
        provenance = build_provenance(config, cases_file, len(cases), scan_started,
                                      cases_sha256)
        paths = write_report(results, output, provenance, overwrite)
    except OSError as exc:
        # The outcome counts are still shown so that findings are not lost with the report.
        typer.echo(summary)
        typer.echo(f"Could not write report: {exc}", err=True)
        return EXIT_OPERATIONAL_ERROR
    typer.echo(f"Wrote {paths[0]} and {paths[1]}")
    typer.echo(summary)
    if outcomes["error"]:
        first = next(r["evidence"][0] for r in results if r["outcome"] == "error")
        typer.echo(f"First error: {_plain(first)}", err=True)
    typer.echo("Outcomes are heuristic indicators, not proof. 'inconclusive' is not a pass.")
    if outcomes["confirmed"]:
        return EXIT_CONFIRMED
    if outcomes["error"]:
        return EXIT_OPERATIONAL_ERROR
    return 0


def _text_summary(data: dict) -> str:
    """A readable summary of a report. The file may be hand-edited, so nothing is assumed
    about the shape of its optional parts."""
    def get(mapping: object, *keys: str) -> object:
        for key in keys:
            mapping = mapping.get(key) if isinstance(mapping, dict) else None
        return "" if mapping is None else mapping

    provenance = data.get("provenance")
    lines = [f"Injektor report generated {_plain(data.get('generated_at', 'at an unknown time'))}"]
    if isinstance(provenance, dict):
        lines.append(f"Target: {_plain(get(provenance, 'target', 'endpoint'))} "
                     f"(model {_plain(get(provenance, 'target', 'model'), 80)})")
        lines.append(f"Cases:  {_plain(get(provenance, 'cases', 'file'))}, "
                     f"sha256 {_plain(get(provenance, 'cases', 'sha256'))}")
    outcomes = get(data["statistics"], "outcomes")
    if isinstance(outcomes, dict):
        lines.append("Outcomes: " + ", ".join(f"{_plain(count)} {_plain(name)}"
                                             for name, count in outcomes.items()))
    results = data.get("results")
    for result in results if isinstance(results, list) else []:
        if not isinstance(result, dict):
            continue
        lines.append("")
        lines.append(f"{_plain(result.get('outcome', '?')):13}{_plain(result.get('severity', '?')):9}"
                     f"{_plain(result.get('test_id', '?'))} ({_plain(result.get('category', '?'))})")
        for label, key in (("evidence", "evidence"), ("excerpt", "excerpts")):
            values = result.get(key)
            for value in values if isinstance(values, list) else []:
                lines.append(f"    {label}: {_plain(value)}")
        if result.get("remediation"):
            lines.append(f"    remediation: {_plain(result['remediation'], 600)}")
    lines += ["", "Outcomes are heuristic indicators, not proof. 'inconclusive' is not a pass."]
    return "\n".join(lines)


@app.command()
def report(path: Path = typer.Argument(..., exists=True, readable=True),
           output_format: str = typer.Option("json", "--format",
                                             help="json (machine-readable summary), text "
                                             "(per-case outcomes and evidence), markdown "
                                             "(summary for a CI job page) or junit (XML test "
                                             "report for CI)"),
           output: Path = typer.Option(None, "--output", "-o",
                                       help="Write to this file (UTF-8) instead of standard "
                                       "output")):
    """View a previously generated JSON report, or convert it for CI."""
    if output_format not in {"json", "text", "markdown", "junit"}:
        raise typer.BadParameter("--format must be json, text, markdown or junit")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        raise typer.BadParameter(f"Could not read report: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("statistics"), dict):
        raise typer.BadParameter("Not an Injektor report: missing 'statistics' object.")
    if output_format == "text":
        content = _text_summary(data) + "\n"
    elif output_format == "markdown":
        content = to_markdown(data)
    elif output_format == "junit":
        content = to_junit(data)
    else:
        summary = {key: data[key] for key in ("generated_at", "provenance", "statistics")
                   if key in data}
        content = json.dumps(summary, indent=2) + "\n"
    if output is not None:
        try:
            output.write_text(content, encoding="utf-8", errors="backslashreplace")
        except OSError as exc:
            raise typer.BadParameter(f"Could not write {output}: {exc.strerror or exc}") from exc
        typer.echo(f"Wrote {output}", err=True)
        return
    # Standard output may be a legacy Windows code page, so it stays ASCII. In XML a
    # character reference keeps the document valid; elsewhere a backslash escape is shown.
    errors = "xmlcharrefreplace" if output_format == "junit" else "backslashreplace"
    typer.echo(content.encode("ascii", errors).decode("ascii"), nl=False)


@app.command()
def demo(mode: str = typer.Option("vulnerable", help="vulnerable or safe"),
         host: str = typer.Option("127.0.0.1", help="Loopback address to bind"),
         port: int = typer.Option(8765, min=1, max=65535, help="TCP port to listen on")):
    """Run the isolated synthetic demo endpoint (intentionally vulnerable by default)."""
    if mode not in {"vulnerable", "safe"}:
        raise typer.BadParameter("mode must be vulnerable or safe")
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise typer.BadParameter("Demo may bind only to loopback.")
    from .demo import serve
    try:
        serve(host, port, mode)
    except (OSError, OverflowError) as exc:
        raise typer.BadParameter(f"Could not start demo on {host}:{port}: {exc}") from exc
    except KeyboardInterrupt:
        typer.echo("Demo stopped.")


if __name__ == "__main__":
    app()
