from __future__ import annotations

from datetime import date
from typing import Optional

import yaml

from safe_pip_compile.exceptions import AllowlistError
from safe_pip_compile.models import AllowlistEntry, Vulnerability


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
            raise AllowlistError(f"Entry {i} must be a mapping with at least 'id' key")

        cve_id = item.get("id")
        if not cve_id:
            raise AllowlistError(f"Entry {i} missing required 'id' field")

        reason = item.get("reason", "")
        expires_raw = item.get("expires")
        expires: Optional[date] = None

        if expires_raw:
            if isinstance(expires_raw, date):
                expires = expires_raw
            elif isinstance(expires_raw, str):
                try:
                    expires = date.fromisoformat(expires_raw)
                except ValueError:
                    raise AllowlistError(
                        f"Entry {i} has invalid 'expires' date: {expires_raw}. "
                        f"Use YYYY-MM-DD format."
                    )

        entries.append(AllowlistEntry(id=str(cve_id), reason=reason, expires=expires))

    return entries


def is_allowed(
    vuln: Vulnerability,
    allowlist: list[AllowlistEntry],
    today: Optional[date] = None,
) -> bool:
    vuln_ids = {vuln.id} | set(vuln.aliases)

    for entry in allowlist:
        if entry.id in vuln_ids:
            if not entry.is_expired(today):
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
