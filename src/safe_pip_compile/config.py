from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from safe_pip_compile.models import Severity


@dataclass
class Config:
    # Core resolution options
    max_iterations: int = 10
    min_severity: Severity = Severity.LOW
    allowlist_path: Optional[str] = None
    strict: bool = True

    # Output / reporting
    output_file: Optional[str] = None
    json_report: Optional[str] = None
    dry_run: bool = False

    # Network / SSL
    cert: Optional[str] = None

    # Cache
    no_cache: bool = False
    refresh_cache: bool = False

    # Verbosity (0 = quiet, 1 = -v, 2 = -vv)
    verbose: int = 0

    def merge_cli(
        self,
        max_iterations: int | None = None,
        min_severity: str | None = None,
        allowlist_path: str | None = None,
        strict: bool | None = None,
        output_file: str | None = None,
        json_report: str | None = None,
        dry_run: bool | None = None,
        cert: str | None = None,
        no_cache: bool | None = None,
        refresh_cache: bool | None = None,
        verbose: int | None = None,
    ) -> Config:
        """Return a new Config with CLI values taking precedence over file config."""
        return Config(
            max_iterations=max_iterations if max_iterations is not None else self.max_iterations,
            min_severity=Severity.from_string(min_severity) if min_severity else self.min_severity,
            allowlist_path=allowlist_path if allowlist_path is not None else self.allowlist_path,
            strict=strict if strict is not None else self.strict,
            output_file=output_file if output_file is not None else self.output_file,
            json_report=json_report if json_report is not None else self.json_report,
            dry_run=dry_run if dry_run is not None else self.dry_run,
            cert=cert if cert is not None else self.cert,
            no_cache=no_cache if no_cache is not None else self.no_cache,
            refresh_cache=refresh_cache if refresh_cache is not None else self.refresh_cache,
            verbose=verbose if verbose is not None else self.verbose,
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

    # ── Core resolution ──────────────────────────────────────────────────────
    if "max-iterations" in tool_config:
        config.max_iterations = int(tool_config["max-iterations"])
    if "min-severity" in tool_config:
        config.min_severity = Severity.from_string(str(tool_config["min-severity"]))
    if "allowlist" in tool_config and tool_config["allowlist"]:
        config.allowlist_path = str(tool_config["allowlist"])
    if "strict" in tool_config:
        config.strict = bool(tool_config["strict"])

    # ── Output / reporting ───────────────────────────────────────────────────
    if "output-file" in tool_config and tool_config["output-file"]:
        config.output_file = str(tool_config["output-file"])
    if "json-report" in tool_config and tool_config["json-report"]:
        config.json_report = str(tool_config["json-report"])
    if "dry-run" in tool_config:
        config.dry_run = bool(tool_config["dry-run"])

    # ── Network / SSL ────────────────────────────────────────────────────────
    if "cert" in tool_config and tool_config["cert"]:
        config.cert = str(tool_config["cert"])

    # ── Cache ────────────────────────────────────────────────────────────────
    if "no-cache" in tool_config:
        config.no_cache = bool(tool_config["no-cache"])
    if "refresh-cache" in tool_config:
        config.refresh_cache = bool(tool_config["refresh-cache"])

    # ── Verbosity ────────────────────────────────────────────────────────────
    if "verbose" in tool_config:
        config.verbose = int(tool_config["verbose"])

    return config
