"""The declared dependency range must not admit a combination that is known to be broken.

Typer 0.12.0 to 0.15.3 declare no upper bound on Click and stop working with Click 8.2 and
later: every invocation, including ``injektor --version``, ends in "Missing command". A
resolver that picked one of them (a constraints file, a lower-bounds check) installed a CLI
that could not run. The CI job ``min-deps`` runs this suite on the declared floor.
"""
import re
from importlib import metadata
from pathlib import Path

import pytest
from packaging import specifiers
from typer.testing import CliRunner

from injektor import __version__
from injektor.cli import app

PYPROJECT = Path(__file__).parents[1] / "pyproject.toml"
# The lowest release whose own requirements always resolve to a Click it works with.
TYPER_FLOOR = "0.15.4"


def declared(name):
    match = re.search(rf'"{name}([^"]*)"', PYPROJECT.read_text(encoding="utf-8"))
    assert match, f"{name} is not declared in pyproject.toml"
    return specifiers.SpecifierSet(match.group(1))


@pytest.mark.parametrize("broken", ["0.12.0", "0.12.5", "0.13.0", "0.13.1", "0.15.1", "0.15.3"])
def test_typer_versions_that_break_with_current_click_are_excluded(broken):
    assert broken not in declared("typer")


def test_typer_floor_is_the_tested_one():
    spec = declared("typer")
    assert TYPER_FLOOR in spec and "0.16.0" in spec and "1.0.0" not in spec


@pytest.mark.parametrize("name", ["typer", "httpx", "PyYAML"])
def test_installed_dependency_is_inside_the_declared_range(name):
    assert metadata.version(name) in declared(name)


def test_cli_dispatches_with_the_installed_typer_and_click():
    """What the broken combination could not do: reach an option, a command and its help."""
    runner = CliRunner()
    version = runner.invoke(app, ["--version"])
    assert version.exit_code == 0 and version.output.strip() == f"injektor {__version__}"
    listed = runner.invoke(app, ["list"])
    assert listed.exit_code == 0 and "direct-override" in listed.output
    for command in ("scan", "list", "report", "demo"):
        shown = runner.invoke(app, [command, "--help"])
        assert shown.exit_code == 0 and "Missing command" not in shown.output
