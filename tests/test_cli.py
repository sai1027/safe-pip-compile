from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from safe_pip_compile.cli import main
from safe_pip_compile.models import CompileResult, CompileStatus, Severity


@pytest.fixture
def runner():
    return CliRunner()


@patch("safe_pip_compile.cli.run_safe_compile")
@patch("safe_pip_compile.cli.load_config")
def test_cli_help(mock_config, mock_compile, runner):
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "CVE-aware pip-compile wrapper" in result.output


@patch("safe_pip_compile.cli.run_safe_compile")
@patch("safe_pip_compile.cli.load_config")
def test_cli_clean_exit_code(mock_config, mock_compile, runner, tmp_path):
    from safe_pip_compile.config import Config

    mock_config.return_value = Config()

    src = tmp_path / "requirements.in"
    src.write_text("django\n")

    mock_compile.return_value = CompileResult(status=CompileStatus.CLEAN)

    result = runner.invoke(main, [str(src)])
    assert result.exit_code == 0

    call_kwargs = mock_compile.call_args[1]
    assert call_kwargs["output_file"] == "requirements.txt"


@patch("safe_pip_compile.cli.run_safe_compile")
@patch("safe_pip_compile.cli.load_config")
def test_cli_uses_custom_output_file(mock_config, mock_compile, runner, tmp_path):
    from safe_pip_compile.config import Config

    mock_config.return_value = Config()

    src = tmp_path / "requirements.in"
    src.write_text("django\n")

    mock_compile.return_value = CompileResult(status=CompileStatus.CLEAN)

    result = runner.invoke(main, [str(src), "-o", "req.txt"])
    assert result.exit_code == 0

    call_kwargs = mock_compile.call_args[1]
    assert call_kwargs["output_file"] == "req.txt"


@patch("safe_pip_compile.cli.run_safe_compile")
@patch("safe_pip_compile.cli.load_config")
def test_cli_warns_when_user_declines_unpin_retry(
    mock_config, mock_compile, runner, tmp_path
):
    from safe_pip_compile.config import Config
    from safe_pip_compile.exceptions import UnsolvableConstraintsError

    mock_config.return_value = Config()

    src = tmp_path / "requirements.in"
    src.write_text("django==3.2.1\n")

    mock_compile.side_effect = UnsolvableConstraintsError(
        constraints=["django>=3.2.25"],
        pip_stderr="Cannot install django==3.2.1",
    )

    result = runner.invoke(main, [str(src), "-o", "req.txt"], input="n\n")

    assert result.exit_code == 2
    assert "dependencies are resolved in req.txt" in result.output
    assert "unresolved CVEs remain" in result.output
    assert "Consider adding some CVEs" not in result.output


@patch("safe_pip_compile.cli.run_safe_compile")
@patch("safe_pip_compile.cli.load_config")
def test_cli_unresolved_strict_exit_code(mock_config, mock_compile, runner, tmp_path):
    from safe_pip_compile.config import Config
    from safe_pip_compile.models import Severity, Vulnerability

    mock_config.return_value = Config()

    src = tmp_path / "requirements.in"
    src.write_text("django\n")

    mock_compile.return_value = CompileResult(
        status=CompileStatus.UNFIXABLE_CVES,
        remaining_vulns=[
            Vulnerability(id="CVE-1", severity=Severity.HIGH)
        ],
    )

    result = runner.invoke(main, [str(src)])
    assert result.exit_code == 1


@patch("safe_pip_compile.cli.run_safe_compile")
@patch("safe_pip_compile.cli.load_config")
def test_cli_passes_min_severity(mock_config, mock_compile, runner, tmp_path):
    from safe_pip_compile.config import Config

    mock_config.return_value = Config()

    src = tmp_path / "requirements.in"
    src.write_text("django\n")

    mock_compile.return_value = CompileResult(status=CompileStatus.CLEAN)

    result = runner.invoke(main, [str(src), "--min-severity", "high"])
    assert result.exit_code == 0

    call_kwargs = mock_compile.call_args[1]
    assert call_kwargs["min_severity"] == Severity.HIGH
