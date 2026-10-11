import json

from typer.testing import CliRunner

from injector.cli import app


def test_scan_writes_json_and_html(tmp_path, monkeypatch):
    import injector.cli as cli

    class Target:
        def ask(self, _prompt):
            return "I cannot reveal hidden information."

    monkeypatch.setattr(cli.TargetConfig, "from_env", lambda: object())
    monkeypatch.setattr(cli, "OpenAICompatibleTarget", lambda _cfg: Target())
    output = tmp_path / "reports"
    result = CliRunner().invoke(app, ["scan", "--output", str(output)])
    assert result.exit_code == 0, result.output
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert report["statistics"]["total"] == 4
    assert (output / "report.html").exists()
    shown = CliRunner().invoke(app, ["report", str(output / "report.json")])
    assert shown.exit_code == 0
