from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from safe_pip_compile.models import Severity


@dataclass
class Config:
    max_iterations: int = 10
    min_severity: Severity = Severity.LOW
    allowlist_path: Optional[str] = None
    strict: bool = True

    def merge_cli(
        self,
        max_iterations: int | None = None,
        min_severity: str | None = None,
        allowlist_path: str | None = None,
        strict: bool | None = None,
    ) -> Config:
        return Config(
            max_iterations=max_iterations if max_iterations is not None else self.max_iterations,
            min_severity=Severity.from_string(min_severity) if min_severity else self.min_severity,
            allowlist_path=allowlist_path if allowlist_path is not None else self.allowlist_path,
            strict=strict if strict is not None else self.strict,
        )


def load_config(pyproject_path: str | None = None) -> Config:
    if pyproject_path and os.path.isfile(pyproject_path):
        return _parse_pyproject(pyproject_path)

    search_dir = Path.cwd()
    for _ in range(10):
        candidate = search_dir / "pyproject.toml"
        if candidate.is_file():
            return _parse_pyproject(str(candidate))
        parent = search_dir.parent
        if parent == search_dir:
            break
        search_dir = parent

    return Config()


def _parse_pyproject(filepath: str) -> Config:
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            return Config()

    try:
        with open(filepath, "rb") as f:
            data = tomllib.load(f)
    except Exception:
        return Config()

    tool_config = data.get("tool", {}).get("safe-pip-compile", {})
    if not tool_config:
        return Config()

    config = Config()

    if "max-iterations" in tool_config:
        config.max_iterations = int(tool_config["max-iterations"])
    if "min-severity" in tool_config:
        config.min_severity = Severity.from_string(str(tool_config["min-severity"]))
    if "allowlist" in tool_config and tool_config["allowlist"]:
        config.allowlist_path = str(tool_config["allowlist"])
    if "strict" in tool_config:
        config.strict = bool(tool_config["strict"])

    return config
