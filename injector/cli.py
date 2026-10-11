"""Typer CLI for listing cases, scanning, reporting, and local demo."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import typer

from .config import TargetConfig, load_cases
from .detection import detect
from .reporting import write_report
from .target import OpenAICompatibleTarget, TargetError

# Locals are never rendered in tracebacks: request frames hold the Authorization header.
app = typer.Typer(help="Evaluate prompt-injection indicators against an authorized LLM endpoint.",
                  pretty_exceptions_show_locals=False)
CASES = Path(__file__).resolve().parent / "cases" / "default.yaml"


@app.command("list")
def list_cases():
    """List the built-in test cases."""
    for case in load_cases(CASES):
        typer.echo(f"{case.id:24} {case.severity:8} {case.category} - {case.description}")


@app.command()
def scan(output: Path = typer.Option(Path("reports"), "--output", help="Report output directory"),
         cases_file: Path = typer.Option(CASES, "--cases", help="YAML case file")):
    """Run the bounded test suite against explicitly configured target variables."""
    try:
        config = TargetConfig.from_env()
        target = OpenAICompatibleTarget(config)
        results = []
        for case in load_cases(cases_file):
            started = datetime.now(timezone.utc).isoformat()
            try:
                result = detect(case, target.ask(case.test_input))
            except TargetError as exc:
                result = {"outcome": "error", "evidence": [str(exc)]}
            results.append({"test_id": case.id, "category": case.category,
                            "severity": case.severity, "timestamp": started, **result})
        paths = write_report(results, output)
        typer.echo(f"Wrote {paths[0]} and {paths[1]}")
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


@app.command()
def report(path: Path = typer.Argument(..., exists=True, readable=True)):
    """View a previously generated JSON report summary."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(f"Could not read report: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("statistics"), dict):
        raise typer.BadParameter("Not an Injector report: missing 'statistics' object.")
    typer.echo(json.dumps(data["statistics"], indent=2))


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
