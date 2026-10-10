from typer.testing import CliRunner
from redforge.cli import app

runner = CliRunner()


def test_cli_flow(tmp_path):
    root = str(tmp_path / "eng")
    assert runner.invoke(app, ["init", "--root", root]).exit_code == 0
    assert runner.invoke(app, ["scope", "add", "127.0.0.1/32", "--reason", "local test", "--root", root]).exit_code == 0
    assert runner.invoke(app, ["scope", "check", "127.0.0.1", "--root", root]).exit_code == 0
    assert runner.invoke(app, ["scope", "check", "8.8.8.8", "--root", root]).exit_code != 0
    assert runner.invoke(app, ["authorize", "--confirm", "--root", root]).exit_code == 0
    report = str(tmp_path / "report.html")
    assert runner.invoke(app, ["report", "--output", report, "--root", root]).exit_code == 0
    assert (tmp_path / "report.html").is_file()
