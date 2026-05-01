from __future__ import annotations

import re

from packaging.requirements import Requirement

from safe_pip_compile.models import ResolvedPackage


_COMMENT_RE = re.compile(r"^\s*#")
_OPTION_RE = re.compile(r"^\s*--")
_HASH_RE = re.compile(r"\s*\\?\s*--hash=")


def parse_requirements(filepath: str) -> list[ResolvedPackage]:
    with open(filepath, encoding="utf-8") as f:
        lines = f.readlines()

    packages: list[ResolvedPackage] = []
    logical_line = ""

    for raw_line in lines:
        line = raw_line.rstrip("\n").rstrip("\r")

        if _COMMENT_RE.match(line) and not logical_line:
            continue
        if not line.strip() and not logical_line:
            continue
        if _OPTION_RE.match(line) and not logical_line:
            continue

        if line.rstrip().endswith("\\"):
            logical_line += line.rstrip().rstrip("\\").strip() + " "
            continue
        else:
            logical_line += line.strip()

        pkg = _parse_line(logical_line)
        if pkg:
            packages.append(pkg)
        logical_line = ""

    if logical_line.strip():
        pkg = _parse_line(logical_line)
        if pkg:
            packages.append(pkg)

    return packages


def _parse_line(line: str) -> ResolvedPackage | None:
    line = _HASH_RE.split(line)[0].strip()

    comment_idx = line.find("#")
    if comment_idx >= 0:
        possible_marker = line[:comment_idx]
        if "==" in possible_marker or ">=" in possible_marker:
            line = possible_marker.strip()
        else:
            line = line[:comment_idx].strip()

    if not line or line.startswith("#") or line.startswith("--"):
        return None

    try:
        req = Requirement(line)
    except Exception:
        return None

    version = ""
    for spec in req.specifier:
        if spec.operator == "==":
            version = spec.version
            break

    if not version:
        return None

    name = req.name.lower().replace("_", "-")
    extras = tuple(sorted(req.extras)) if req.extras else ()
    return ResolvedPackage(name=name, version=version, extras=extras)
