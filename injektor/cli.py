"""Typer CLI for listing cases, scanning, reporting, and local demo."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import typer

from .config import AttackCase, TargetConfig, load_cases
from .detection import detect, score
from .reporting import build_provenance, existing_reports, write_report
from .target import OpenAICompatibleTarget, TargetError

# Locals are never rendered in tracebacks: request frames hold the Authorization header.
app = typer.Typer(help="Evaluate prompt-injection indicators against an authorized LLM endpoint.",
                  pretty_exceptions_show_locals=False)
CASES = Path(__file__).resolve().parent / "cases" / "default.yaml"
# 2 is reserved by the CLI framework for invalid usage and configuration.
EXIT_CONFIRMED, EXIT_OPERATIONAL_ERROR = 1, 3


@app.command("list")
def list_cases():
    """List the built-in test cases."""
    for case in load_cases(CASES):
        typer.echo(f"{case.id:24} {case.severity:8} {case.category} - {case.description}")


@app.command()
def scan(output: Path = typer.Option(Path("reports"), "--output", help="Report output directory"),
         cases_file: Path = typer.Option(CASES, "--cases", help="YAML case file"),
         overwrite: bool = typer.Option(False, "--overwrite",
                                        help="Replace an existing report in the output directory")):
    """Run the bounded test suite against explicitly configured target variables.

    Exit status: 0 no confirmed finding, 1 confirmed finding, 2 invalid usage or
    configuration, 3 operational error (a case could not be evaluated, the report could
    not be written, or the scan failed unexpectedly). A confirmed finding takes precedence
    over operational errors.
    """
    try:
        config = TargetConfig.from_env()
        cases = load_cases(cases_file)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    # Checked before any request is sent, so a refused overwrite costs the target nothing.
    existing = existing_reports(output)
    if existing and not overwrite:
        raise typer.BadParameter(f"{existing[0]} already exists. Choose another --output "
                                 "directory or pass --overwrite.")
    try:
        status = _run_scan(config, cases, cases_file, output, overwrite)
    except Exception as exc:
        # Python would exit with status 1 here, which is reserved for confirmed findings.
        # Only the type is shown: exception messages can embed request data.
        typer.echo(f"Scan aborted by an unexpected internal error ({type(exc).__name__}).", err=True)
        status = EXIT_OPERATIONAL_ERROR
    if status:
        raise typer.Exit(status)


def _run_scan(config: TargetConfig, cases: list[AttackCase], cases_file: Path, output: Path,
              overwrite: bool) -> int:
    target = OpenAICompatibleTarget(config)
    scan_started = datetime.now(timezone.utc).isoformat()
    results = []
    for case in cases:
        started = datetime.now(timezone.utc).isoformat()
        try:
            result = detect(case, target.ask(case.test_input))
        except TargetError as exc:
            result = {"outcome": "error", "evidence": [str(exc)]}
        results.append({"test_id": case.id, "category": case.category,
                        "severity": case.severity, "timestamp": started, **result})
    outcomes = score(results)["outcomes"]
    summary = f"{len(results)} cases: " + ", ".join(f"{n} {name}" for name, n in outcomes.items())
    try:
        provenance = build_provenance(config, cases_file, len(cases), scan_started)
        paths = write_report(results, output, provenance, overwrite)
    except OSError as exc:
        # The outcome counts are still shown so that findings are not lost with the report.
        typer.echo(summary)
        typer.echo(f"Could not write report: {exc}", err=True)
        return EXIT_OPERATIONAL_ERROR
    typer.echo(f"Wrote {paths[0]} and {paths[1]}")
    typer.echo(summary)
    if outcomes["confirmed"]:
        return EXIT_CONFIRMED
    if outcomes["error"]:
        return EXIT_OPERATIONAL_ERROR
    return 0


@app.command()
def report(path: Path = typer.Argument(..., exists=True, readable=True)):
    """View a previously generated JSON report summary."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(f"Could not read report: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("statistics"), dict):
        raise typer.BadParameter("Not an Injektor report: missing 'statistics' object.")
    summary = {key: data[key] for key in ("generated_at", "provenance", "statistics") if key in data}
    typer.echo(json.dumps(summary, indent=2))


@app.command()
def demo(mode: str = typer.Option("vulnerable", help="vulnerable or safe"),
         host: str = typer.Option("127.0.0.1"), port: int = typer.Option(8765)):
    """Run the isolated synthetic demo endpoint (intentionally vulnerable by default)."""
    if mode not in {"vulnerable", "safe"}:
        raise typer.BadParameter("mode must be vulnerable or safe")
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise typer.BadParameter("Demo may bind only to loopback.")
    from .demo import serve
    try:
        serve(host, port, mode)
    except OSError as exc:
        raise typer.BadParameter(f"Could not start demo on {host}:{port}: {exc}") from exc


if __name__ == "__main__":
    app()
