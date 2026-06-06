from __future__ import annotations

from datetime import date
from typing import Optional

import yaml
from packaging.specifiers import InvalidSpecifier, SpecifierSet

from safe_pip_compile.exceptions import AllowlistError
from safe_pip_compile.models import AllowlistEntry, Severity, Vulnerability


def _parse_expires(raw, entry_index: int) -> Optional[date]:
    """Parse an `expires` value (date object or ISO-8601 string) into a date."""
    if not raw:
        return None
    if isinstance(raw, date):
        return raw
    if isinstance(raw, str):
        try:
            return date.fromisoformat(raw)
        except ValueError:
            raise AllowlistError(
                f"Entry {entry_index} has invalid 'expires' date: {raw}. "
                f"Use YYYY-MM-DD format."
            )
    raise AllowlistError(
        f"Entry {entry_index} has unsupported 'expires' type: {type(raw).__name__}"
    )


def _parse_versions(raw, entry_index: int) -> tuple[str, ...]:
    """Parse and validate the `versions` list of PEP 440 specifier strings."""
    if not raw:
        return ()
    if not isinstance(raw, list):
        raise AllowlistError(
            f"Entry {entry_index} 'versions' must be a list of version specifier "
            f"strings, e.g. [\">=2.0\", \"<3.0\"]"
        )
    specs: list[str] = []
    for spec_str in raw:
        if not isinstance(spec_str, str):
            raise AllowlistError(
                f"Entry {entry_index} 'versions' contains a non-string value: {spec_str!r}"
            )
        try:
            SpecifierSet(spec_str)  # validate early
        except InvalidSpecifier:
            raise AllowlistError(
                f"Entry {entry_index} has invalid version specifier: {spec_str!r}. "
                f"Use PEP 440 format, e.g. \">=2.0\", \"==1.5.3\", \"<3.0\"."
            )
        specs.append(spec_str)
    return tuple(specs)


def load_allowlist(filepath: str) -> list[AllowlistEntry]:
    try:
        with open(filepath, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except FileNotFoundError:
        raise AllowlistError(f"Allowlist file not found: {filepath}")
    except yaml.YAMLError as e:
        raise AllowlistError(f"Invalid YAML in allowlist: {e}")

    if not isinstance(data, dict):
        raise AllowlistError("Allowlist must be a YAML mapping with 'allowed_cves' key")

    entries_data = data.get("allowed_cves", [])
    if not isinstance(entries_data, list):
        raise AllowlistError("'allowed_cves' must be a list")

    entries: list[AllowlistEntry] = []
    for i, item in enumerate(entries_data):
        if not isinstance(item, dict):
            raise AllowlistError(f"Entry {i} must be a mapping with at least 'id' or 'package' key")

        cve_id = str(item["id"]) if item.get("id") else ""
        package = str(item["package"]).strip() if item.get("package") else ""

        if not cve_id and not package:
            raise AllowlistError(
                f"Entry {i} must have at least one of 'id' (CVE/GHSA identifier) "
                f"or 'package' (library name)"
            )

        versions = _parse_versions(item.get("versions"), i)
        expires = _parse_expires(item.get("expires"), i)
        reason = item.get("reason", "")

        # Parse optional per-package severity cap
        severity_raw = item.get("severity")
        severity: Optional[Severity] = None
        if severity_raw is not None:
            severity = Severity.from_string(str(severity_raw))
            if severity == Severity.UNKNOWN:
                raise AllowlistError(
                    f"Entry {i} has unrecognised 'severity' value: {severity_raw!r}. "
                    f"Use one of: low, medium, high, critical."
                )

        entries.append(
            AllowlistEntry(
                id=cve_id,
                package=package,
                versions=versions,
                severity=severity,
                reason=reason,
                expires=expires,
            )
        )

    return entries


def is_allowed(
    vuln: Vulnerability,
    allowlist: list[AllowlistEntry],
    today: Optional[date] = None,
) -> bool:
    """Return True if *vuln* is suppressed by any entry in *allowlist*.

    Matching priority:
    1. CVE-id match (entry.id matches vuln's ID or an alias) — always suppresses
       regardless of severity, provided the entry has not expired.
    2. Package-based match (entry.package matches vuln.affected_package) — suppresses
       when version specifiers and per-package severity cap also match.
    """
    vuln_ids = {vuln.id} | set(vuln.aliases)

    for entry in allowlist:
        if entry.is_expired(today):
            continue

        # --- Priority 1: CVE-id match ---
        if entry.id and entry.id in vuln_ids:
            return True

        # --- Priority 2: package-based match ---
        if entry.package and vuln.affected_package:
            if entry.matches_package(vuln.affected_package, vuln.affected_version):
                # Apply per-package severity cap if set.
                # "suppress at or below this severity" — same logic as --min-severity
                # but inverted: we suppress when vuln severity is <= cap.
                if entry.severity is not None:
                    # UNKNOWN severity is treated as always suppressed (mirrors meets_threshold)
                    if vuln.severity != Severity.UNKNOWN and vuln.severity.value > entry.severity.value:
                        continue  # above the cap → not suppressed by this entry
                return True

    return False


def filter_allowed(
    vulns: list[Vulnerability],
    allowlist: list[AllowlistEntry],
    today: Optional[date] = None,
) -> tuple[list[Vulnerability], list[Vulnerability]]:
    """Returns (blocking_vulns, allowed_vulns)."""
    blocking = []
    allowed = []

    for v in vulns:
        if is_allowed(v, allowlist, today):
            allowed.append(v)
        else:
            blocking.append(v)

    return blocking, allowed
