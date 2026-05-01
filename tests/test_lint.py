import subprocess
import sys
import pytest

def test_ruff_lint():
    """Run ruff linter and check for issues."""
    result = subprocess.run(
        [sys.executable, "-m", "ruff", "check", "src", "tests"],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        message = (
            "\nLinter (ruff) found issues:\n"
            f"{result.stdout}\n"
            "SUGGESTION: Please remove unused imports or other linting violations. "
            "You can run 'ruff check --fix' to automatically resolve most issues."
        )
        pytest.fail(message)
