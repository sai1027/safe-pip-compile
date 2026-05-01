from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from safe_pip_compile.models import Vulnerability


class SafePipCompileError(Exception):
    pass


class PipCompileError(SafePipCompileError):
    def __init__(self, message: str, returncode: int = 1, stderr: str = ""):
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(message)


class UnsolvableConstraintsError(SafePipCompileError):
    def __init__(self, constraints: list[str], pip_stderr: str = ""):
        self.constraints = constraints
        self.pip_stderr = pip_stderr
        msg = (
            f"Constraints made resolution impossible.\n"
            f"Constraints: {', '.join(constraints)}\n"
            f"pip-compile output: {pip_stderr[:500]}"
        )
        super().__init__(msg)


class OSVAPIError(SafePipCompileError):
    def __init__(self, status_code: int, response_body: str = ""):
        self.status_code = status_code
        self.response_body = response_body
        super().__init__(f"OSV.dev API error (HTTP {status_code}): {response_body[:200]}")


class OSVNetworkError(SafePipCompileError):
    def __init__(self, message: str = "Cannot reach OSV.dev API"):
        super().__init__(message)


class AllowlistError(SafePipCompileError):
    pass


class MaxIterationsExceeded(SafePipCompileError):
    def __init__(self, remaining_vulns: list[Vulnerability]):
        self.remaining_vulns = remaining_vulns
        ids = ", ".join(v.display_id for v in remaining_vulns[:5])
        super().__init__(f"Max iterations reached. Remaining CVEs: {ids}")
