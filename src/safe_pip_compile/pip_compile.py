from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass


@dataclass
class PipCompileResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def failed(self) -> bool:
        return self.returncode != 0


def find_pip_compile() -> list[str]:
    exe = shutil.which("pip-compile")
    if exe:
        return [exe]
    return [sys.executable, "-m", "piptools", "compile"]


def run_pip_compile(
    src_files: list[str],
    output_file: str | None = None,
    extra_args: list[str] | None = None,
    constraints_file: str | None = None,
    timeout: int = 300,
) -> PipCompileResult:
    cmd = find_pip_compile()
    cmd.extend(src_files)

    if output_file:
        cmd.extend(["-o", output_file])

    if constraints_file:
        cmd.extend(["-c", constraints_file])

    if extra_args:
        cmd.extend(extra_args)

    env = os.environ.copy()
    env["CUSTOM_COMPILE_COMMAND"] = "safe-pip-compile"

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except FileNotFoundError:
        return PipCompileResult(
            returncode=127,
            stdout="",
            stderr="pip-compile not found. Install pip-tools: pip install pip-tools",
        )
    except subprocess.TimeoutExpired:
        return PipCompileResult(
            returncode=124,
            stdout="",
            stderr=f"pip-compile timed out after {timeout} seconds",
        )

    return PipCompileResult(
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )
