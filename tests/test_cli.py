from typer.testing import CliRunner

from injector.cli import app


def test_list_command_runs():
    result = CliRunner().invoke(app, ["list"])
    assert result.exit_code == 0
    assert "direct-override" in result.stdout
