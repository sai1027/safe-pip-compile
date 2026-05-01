from __future__ import annotations

from packaging.version import Version

from safe_pip_compile.models import ResolvedPackage, Vulnerability


def generate_constraints(
    vulnerabilities: list[Vulnerability],
    current_packages: list[ResolvedPackage],
) -> list[str]:
    pkg_versions: dict[str, str] = {
        pkg.normalized_name: pkg.version for pkg in current_packages
    }

    pkg_constraints: dict[str, Version | None] = {}
    pkg_exclusions: dict[str, set[str]] = {}

    for vuln in vulnerabilities:
        pkg_name = vuln.affected_package.lower().replace("_", "-")
        if not pkg_name:
            continue

        current_ver = pkg_versions.get(pkg_name)
        if not current_ver:
            continue

        if vuln.fixed_versions:
            best_fix = _find_best_fix_version(vuln.fixed_versions, current_ver)
            if best_fix:
                existing = pkg_constraints.get(pkg_name)
                if existing is None or best_fix > existing:
                    pkg_constraints[pkg_name] = best_fix
            else:
                pkg_exclusions.setdefault(pkg_name, set()).add(current_ver)
        else:
            pkg_exclusions.setdefault(pkg_name, set()).add(current_ver)

    lines: list[str] = []

    for pkg_name, min_ver in sorted(pkg_constraints.items()):
        if min_ver is not None:
            lines.append(f"{pkg_name}>={min_ver}")

    for pkg_name, excluded in sorted(pkg_exclusions.items()):
        if pkg_name in pkg_constraints:
            continue
        parts = ",".join(f"!={v}" for v in sorted(excluded))
        lines.append(f"{pkg_name}{parts}")

    return lines


def _find_best_fix_version(
    fixed_versions: tuple[str, ...], current_version: str
) -> Version | None:
    """Find lowest fixed version > current version."""
    try:
        current = Version(current_version)
    except Exception:
        return None

    candidates: list[Version] = []
    for v in fixed_versions:
        try:
            parsed = Version(v)
            if parsed > current:
                candidates.append(parsed)
        except Exception:
            continue

    if not candidates:
        return None

    return min(candidates)


def merge_constraints(existing: list[str], new: list[str]) -> list[str]:
    """Merge constraint lists, keeping the strictest constraint per package."""
    pkg_map: dict[str, str] = {}

    for line in existing + new:
        pkg_name = _extract_package_name(line)
        if not pkg_name:
            continue

        if pkg_name in pkg_map:
            pkg_map[pkg_name] = _stricter_constraint(pkg_map[pkg_name], line)
        else:
            pkg_map[pkg_name] = line

    return sorted(pkg_map.values())


def _extract_package_name(constraint: str) -> str:
    for sep in (">=", "!=", "==", "<=", ">", "<"):
        idx = constraint.find(sep)
        if idx > 0:
            return constraint[:idx].strip().lower()
    return constraint.strip().lower()


def _stricter_constraint(a: str, b: str) -> str:
    """Pick whichever constraint is more restrictive."""
    ver_a = _extract_version(a)
    ver_b = _extract_version(b)

    if ver_a is None:
        return b
    if ver_b is None:
        return a

    if ">=" in a and ">=" in b:
        return a if ver_a >= ver_b else b
    if "!=" in a and ">=" in b:
        return b
    if ">=" in a and "!=" in b:
        return a

    return b


def _extract_version(constraint: str) -> Version | None:
    for sep in (">=", "!=", "==", "<=", ">", "<"):
        idx = constraint.find(sep)
        if idx >= 0:
            ver_str = constraint[idx + len(sep):].split(",")[0].strip()
            try:
                return Version(ver_str)
            except Exception:
                return None
    return None
