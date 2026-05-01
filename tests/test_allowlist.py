import os
import tempfile
from datetime import date

import pytest

from safe_pip_compile.allowlist import filter_allowed, is_allowed, load_allowlist
from safe_pip_compile.exceptions import AllowlistError
from safe_pip_compile.models import AllowlistEntry, Severity, Vulnerability


def test_load_allowlist(sample_allowlist_path):
    entries = load_allowlist(sample_allowlist_path)
    assert len(entries) == 2
    assert entries[0].id == "CVE-2024-12345"
    assert entries[0].reason == "Not applicable - we don't use QuerySet.values() with user input"
    assert entries[0].expires == date(2027, 12, 31)
    assert entries[1].id == "GHSA-urllib3-vuln"
    assert entries[1].expires is None


def test_load_allowlist_missing_file():
    with pytest.raises(AllowlistError, match="not found"):
        load_allowlist("/nonexistent/path.yaml")


def test_load_allowlist_invalid_yaml():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(": : invalid yaml [[[")
        path = f.name

    try:
        with pytest.raises(AllowlistError, match="Invalid YAML"):
            load_allowlist(path)
    finally:
        os.unlink(path)


def test_load_allowlist_missing_id():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("allowed_cves:\n  - reason: 'no id'\n")
        path = f.name

    try:
        with pytest.raises(AllowlistError, match="missing required 'id'"):
            load_allowlist(path)
    finally:
        os.unlink(path)


def test_is_allowed_by_primary_id():
    vuln = Vulnerability(id="CVE-2024-12345", severity=Severity.HIGH)
    allowlist = [AllowlistEntry(id="CVE-2024-12345", reason="ok")]

    assert is_allowed(vuln, allowlist) is True


def test_is_allowed_by_alias():
    vuln = Vulnerability(
        id="GHSA-xxxx",
        aliases=("CVE-2024-12345",),
        severity=Severity.HIGH,
    )
    allowlist = [AllowlistEntry(id="CVE-2024-12345", reason="ok")]

    assert is_allowed(vuln, allowlist) is True


def test_not_allowed():
    vuln = Vulnerability(id="CVE-2024-99999", severity=Severity.HIGH)
    allowlist = [AllowlistEntry(id="CVE-2024-12345", reason="ok")]

    assert is_allowed(vuln, allowlist) is False


def test_expired_entry():
    vuln = Vulnerability(id="CVE-2024-12345", severity=Severity.HIGH)
    allowlist = [
        AllowlistEntry(id="CVE-2024-12345", reason="ok", expires=date(2020, 1, 1))
    ]

    assert is_allowed(vuln, allowlist, today=date(2024, 6, 1)) is False


def test_filter_allowed():
    vulns = [
        Vulnerability(id="CVE-1", severity=Severity.HIGH),
        Vulnerability(id="CVE-2", severity=Severity.MEDIUM),
        Vulnerability(id="CVE-3", severity=Severity.LOW),
    ]
    allowlist = [AllowlistEntry(id="CVE-2", reason="ok")]

    blocking, allowed = filter_allowed(vulns, allowlist)
    assert len(blocking) == 2
    assert len(allowed) == 1
    assert allowed[0].id == "CVE-2"
