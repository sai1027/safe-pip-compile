"""Tests for safe_pip_compile.allowlist — CVE-id and package-based entries."""

import os
import tempfile
from datetime import date

import pytest

from safe_pip_compile.allowlist import filter_allowed, is_allowed, load_allowlist
from safe_pip_compile.exceptions import AllowlistError
from safe_pip_compile.models import AllowlistEntry, Severity, Vulnerability


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_vuln(
    cve_id="CVE-2024-00001",
    aliases=(),
    severity=Severity.HIGH,
    affected_package="requests",
    affected_version="2.28.0",
) -> Vulnerability:
    return Vulnerability(
        id=cve_id,
        aliases=aliases,
        severity=severity,
        affected_package=affected_package,
        affected_version=affected_version,
    )


def _write_yaml(content: str) -> str:
    """Write *content* to a temp YAML file and return its path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
    f.write(content)
    f.close()
    return f.name


# ===========================================================================
# load_allowlist — parsing
# ===========================================================================


class TestLoadAllowlist:
    def test_load_fixture_entry_count(self, sample_allowlist_path):
        """Sample fixture should load all 6 entries without error."""
        entries = load_allowlist(sample_allowlist_path)
        assert len(entries) == 6

    def test_load_fixture_cve_id_entry(self, sample_allowlist_path):
        """First entry: CVE-id with reason and expiry."""
        entries = load_allowlist(sample_allowlist_path)
        e = entries[0]
        assert e.id == "CVE-2024-12345"
        assert e.expires == date(2027, 12, 31)
        assert e.package == ""

    def test_load_fixture_ghsa_entry(self, sample_allowlist_path):
        """Second entry: GHSA id, no expiry."""
        entries = load_allowlist(sample_allowlist_path)
        e = entries[1]
        assert e.id == "GHSA-urllib3-vuln"
        assert e.expires is None

    def test_load_fixture_package_wildcard(self, sample_allowlist_path):
        """Third entry: package-only (wildcard all versions, no severity cap)."""
        entries = load_allowlist(sample_allowlist_path)
        e = entries[2]
        assert e.package == "requests"
        assert e.id == ""
        assert e.versions == ()
        assert e.severity is None

    def test_load_fixture_package_with_severity(self, sample_allowlist_path):
        """Fourth entry: package with severity cap."""
        entries = load_allowlist(sample_allowlist_path)
        e = entries[3]
        assert e.package == "pillow"
        assert e.severity == Severity.MEDIUM

    def test_load_fixture_package_with_version_range(self, sample_allowlist_path):
        """Fifth entry: package with version range and expiry."""
        entries = load_allowlist(sample_allowlist_path)
        e = entries[4]
        assert e.package == "django"
        assert e.versions == (">=3.2.0", "<4.0.0")
        assert e.expires == date(2028, 4, 1)

    def test_load_fixture_package_with_pinned_version(self, sample_allowlist_path):
        """Sixth entry: package pinned to an exact version."""
        entries = load_allowlist(sample_allowlist_path)
        e = entries[5]
        assert e.package == "cryptography"
        assert e.versions == ("==41.0.0",)

    def test_missing_file(self):
        with pytest.raises(AllowlistError, match="not found"):
            load_allowlist("/nonexistent/path.yaml")

    def test_invalid_yaml(self):
        path = _write_yaml(": : invalid yaml [[[")
        try:
            with pytest.raises(AllowlistError, match="Invalid YAML"):
                load_allowlist(path)
        finally:
            os.unlink(path)

    def test_missing_id_and_package_raises(self):
        """An entry without 'id' AND 'package' must raise."""
        path = _write_yaml("allowed_cves:\n  - reason: 'no id or package'\n")
        try:
            with pytest.raises(AllowlistError, match="must have at least one of"):
                load_allowlist(path)
        finally:
            os.unlink(path)

    def test_invalid_version_specifier_raises(self):
        path = _write_yaml(
            "allowed_cves:\n"
            "  - package: requests\n"
            "    versions: [\"!!notaspec\"]\n"
        )
        try:
            with pytest.raises(AllowlistError, match="invalid version specifier"):
                load_allowlist(path)
        finally:
            os.unlink(path)

    def test_versions_not_a_list_raises(self):
        path = _write_yaml(
            "allowed_cves:\n"
            "  - package: requests\n"
            "    versions: \">=2.0\"\n"  # string instead of list
        )
        try:
            with pytest.raises(AllowlistError, match="must be a list"):
                load_allowlist(path)
        finally:
            os.unlink(path)

    def test_invalid_severity_raises(self):
        path = _write_yaml(
            "allowed_cves:\n"
            "  - package: requests\n"
            "    severity: extreme\n"
        )
        try:
            with pytest.raises(AllowlistError, match="unrecognised 'severity'"):
                load_allowlist(path)
        finally:
            os.unlink(path)

    def test_entry_with_both_id_and_package(self):
        """An entry may have both id and package — both fields should be set."""
        path = _write_yaml(
            "allowed_cves:\n"
            "  - id: CVE-2024-99999\n"
            "    package: requests\n"
            "    reason: always suppress this CVE\n"
        )
        try:
            entries = load_allowlist(path)
            assert entries[0].id == "CVE-2024-99999"
            assert entries[0].package == "requests"
        finally:
            os.unlink(path)


# ===========================================================================
# is_allowed — CVE-id matching (existing behaviour)
# ===========================================================================


class TestIsAllowedByCveId:
    def test_allowed_by_primary_id(self):
        vuln = _make_vuln(cve_id="CVE-2024-12345")
        allowlist = [AllowlistEntry(id="CVE-2024-12345", reason="ok")]
        assert is_allowed(vuln, allowlist) is True

    def test_allowed_by_alias(self):
        vuln = _make_vuln(cve_id="GHSA-xxxx", aliases=("CVE-2024-12345",))
        allowlist = [AllowlistEntry(id="CVE-2024-12345", reason="ok")]
        assert is_allowed(vuln, allowlist) is True

    def test_not_allowed_unknown_id(self):
        vuln = _make_vuln(cve_id="CVE-2024-99999")
        allowlist = [AllowlistEntry(id="CVE-2024-12345", reason="ok")]
        assert is_allowed(vuln, allowlist) is False

    def test_expired_cve_entry_not_allowed(self):
        vuln = _make_vuln(cve_id="CVE-2024-12345")
        allowlist = [AllowlistEntry(id="CVE-2024-12345", expires=date(2020, 1, 1))]
        assert is_allowed(vuln, allowlist, today=date(2024, 6, 1)) is False


# ===========================================================================
# is_allowed — package-based matching
# ===========================================================================


class TestIsAllowedByPackage:
    def test_package_wildcard_any_version(self):
        """Package entry with no versions suppresses all versions."""
        vuln = _make_vuln(affected_package="requests", affected_version="2.31.0")
        allowlist = [AllowlistEntry(package="requests")]
        assert is_allowed(vuln, allowlist) is True

    def test_package_wildcard_different_version(self):
        """Wildcard applies regardless of which version is resolved."""
        vuln = _make_vuln(affected_package="requests", affected_version="1.0.0")
        allowlist = [AllowlistEntry(package="requests")]
        assert is_allowed(vuln, allowlist) is True

    def test_package_pinned_version_match(self):
        """versions: [==2.28.0] matches exactly 2.28.0."""
        vuln = _make_vuln(affected_package="requests", affected_version="2.28.0")
        allowlist = [AllowlistEntry(package="requests", versions=("==2.28.0",))]
        assert is_allowed(vuln, allowlist) is True

    def test_package_pinned_version_mismatch(self):
        """versions: [==2.28.0] does NOT match 2.29.0."""
        vuln = _make_vuln(affected_package="requests", affected_version="2.29.0")
        allowlist = [AllowlistEntry(package="requests", versions=("==2.28.0",))]
        assert is_allowed(vuln, allowlist) is False

    def test_package_version_range_inside(self):
        """versions: [>=2.0, <3.0] matches 2.5.1."""
        vuln = _make_vuln(affected_package="django", affected_version="2.5.1")
        allowlist = [AllowlistEntry(package="django", versions=(">=2.0", "<3.0"))]
        assert is_allowed(vuln, allowlist) is True

    def test_package_version_range_outside(self):
        """versions: [>=2.0, <3.0] does NOT match 3.1.0."""
        vuln = _make_vuln(affected_package="django", affected_version="3.1.0")
        allowlist = [AllowlistEntry(package="django", versions=(">=2.0", "<3.0"))]
        assert is_allowed(vuln, allowlist) is False

    def test_package_name_normalisation(self):
        """Package names are normalised: 'Pillow' matches 'pillow', underscores match dashes."""
        vuln = _make_vuln(affected_package="Pillow", affected_version="9.5.0")
        allowlist = [AllowlistEntry(package="pillow")]
        assert is_allowed(vuln, allowlist) is True

    def test_package_underscore_dash_normalisation(self):
        """'my_package' in vuln matches 'my-package' in entry."""
        vuln = _make_vuln(affected_package="my_package", affected_version="1.0.0")
        allowlist = [AllowlistEntry(package="my-package")]
        assert is_allowed(vuln, allowlist) is True

    def test_different_package_not_matched(self):
        """An entry for 'requests' does not suppress 'urllib3' vulns."""
        vuln = _make_vuln(affected_package="urllib3", affected_version="1.26.0")
        allowlist = [AllowlistEntry(package="requests")]
        assert is_allowed(vuln, allowlist) is False

    def test_package_expired_entry_not_allowed(self):
        vuln = _make_vuln(affected_package="requests", affected_version="2.28.0")
        allowlist = [AllowlistEntry(package="requests", expires=date(2020, 1, 1))]
        assert is_allowed(vuln, allowlist, today=date(2024, 6, 1)) is False


# ===========================================================================
# is_allowed — per-package severity cap
# ===========================================================================


class TestPackageSeverityCap:
    def test_severity_cap_suppresses_below(self):
        """severity: medium suppresses a LOW vuln."""
        vuln = _make_vuln(severity=Severity.LOW, affected_package="pillow", affected_version="9.5.0")
        allowlist = [AllowlistEntry(package="pillow", severity=Severity.MEDIUM)]
        assert is_allowed(vuln, allowlist) is True

    def test_severity_cap_suppresses_at_level(self):
        """severity: medium suppresses a MEDIUM vuln (at the boundary)."""
        vuln = _make_vuln(severity=Severity.MEDIUM, affected_package="pillow", affected_version="9.5.0")
        allowlist = [AllowlistEntry(package="pillow", severity=Severity.MEDIUM)]
        assert is_allowed(vuln, allowlist) is True

    def test_severity_cap_does_not_suppress_above(self):
        """severity: medium does NOT suppress a HIGH vuln."""
        vuln = _make_vuln(severity=Severity.HIGH, affected_package="pillow", affected_version="9.5.0")
        allowlist = [AllowlistEntry(package="pillow", severity=Severity.MEDIUM)]
        assert is_allowed(vuln, allowlist) is False

    def test_severity_cap_does_not_suppress_critical(self):
        """severity: medium does NOT suppress a CRITICAL vuln."""
        vuln = _make_vuln(severity=Severity.CRITICAL, affected_package="pillow", affected_version="9.5.0")
        allowlist = [AllowlistEntry(package="pillow", severity=Severity.MEDIUM)]
        assert is_allowed(vuln, allowlist) is False

    def test_no_severity_cap_suppresses_critical(self):
        """Package entry with no severity cap suppresses even CRITICAL."""
        vuln = _make_vuln(severity=Severity.CRITICAL, affected_package="requests", affected_version="2.0.0")
        allowlist = [AllowlistEntry(package="requests")]
        assert is_allowed(vuln, allowlist) is True


# ===========================================================================
# is_allowed — CVE-id overrides package severity cap
# ===========================================================================


class TestCveIdOverridesPackageSeverity:
    def test_cve_id_suppresses_critical_despite_medium_cap(self):
        """CVE-id entry always suppresses, even if a sibling package entry would not.

        Scenario:
        - package entry for 'requests' caps at medium (LOW/MEDIUM suppressed)
        - A separate CVE-id entry lists a CRITICAL vuln explicitly
        - The CRITICAL vuln SHOULD be suppressed because the id entry wins.
        """
        critical_vuln = _make_vuln(
            cve_id="CVE-2024-CRIT",
            severity=Severity.CRITICAL,
            affected_package="requests",
            affected_version="2.28.0",
        )
        allowlist = [
            AllowlistEntry(package="requests", severity=Severity.MEDIUM),  # cap at medium
            AllowlistEntry(id="CVE-2024-CRIT", reason="always suppress this one"),
        ]
        assert is_allowed(critical_vuln, allowlist) is True

    def test_high_vuln_not_suppressed_when_only_package_cap_medium(self):
        """Without a CVE-id entry, a HIGH vuln is NOT suppressed by medium cap."""
        high_vuln = _make_vuln(
            cve_id="CVE-2024-HIGH",
            severity=Severity.HIGH,
            affected_package="requests",
            affected_version="2.28.0",
        )
        allowlist = [AllowlistEntry(package="requests", severity=Severity.MEDIUM)]
        assert is_allowed(high_vuln, allowlist) is False

    def test_combined_entry_id_plus_package(self):
        """An entry with both id and package: id match wins for that CVE."""
        critical_vuln = _make_vuln(
            cve_id="CVE-2024-CRIT",
            severity=Severity.CRITICAL,
            affected_package="requests",
            affected_version="2.28.0",
        )
        # Single entry with both id and package — id match fires first
        allowlist = [
            AllowlistEntry(
                id="CVE-2024-CRIT",
                package="requests",
                severity=Severity.LOW,  # would not suppress CRITICAL via package match
                reason="explicit override",
            )
        ]
        assert is_allowed(critical_vuln, allowlist) is True


# ===========================================================================
# filter_allowed — mixed CVE-id + package entries
# ===========================================================================


class TestFilterAllowed:
    def test_filter_cve_id_only(self):
        vulns = [
            _make_vuln("CVE-1", affected_package="pkg-a", affected_version="1.0"),
            _make_vuln("CVE-2", affected_package="pkg-b", affected_version="1.0"),
            _make_vuln("CVE-3", affected_package="pkg-c", affected_version="1.0"),
        ]
        allowlist = [AllowlistEntry(id="CVE-2")]
        blocking, allowed = filter_allowed(vulns, allowlist)
        assert len(blocking) == 2
        assert len(allowed) == 1
        assert allowed[0].id == "CVE-2"

    def test_filter_package_wildcard(self):
        """All CVEs for a suppressed package are filtered out."""
        vulns = [
            _make_vuln("CVE-1", affected_package="requests", affected_version="2.28.0"),
            _make_vuln("CVE-2", affected_package="requests", affected_version="2.28.0"),
            _make_vuln("CVE-3", affected_package="urllib3", affected_version="1.26.0"),
        ]
        allowlist = [AllowlistEntry(package="requests")]
        blocking, allowed = filter_allowed(vulns, allowlist)
        assert len(allowed) == 2
        assert len(blocking) == 1
        assert blocking[0].id == "CVE-3"

    def test_filter_mixed_id_and_package(self):
        """CVE-id entries and package entries both contribute to filtering."""
        vulns = [
            # suppressed by CVE-id entry
            _make_vuln("CVE-KNOWN", affected_package="urllib3", affected_version="1.26.0", severity=Severity.HIGH),
            # suppressed by package entry (LOW <= medium cap)
            _make_vuln("CVE-LOW", affected_package="pillow", affected_version="9.5.0", severity=Severity.LOW),
            # NOT suppressed: HIGH is above medium cap for pillow
            _make_vuln("CVE-HIGH", affected_package="pillow", affected_version="9.5.0", severity=Severity.HIGH),
            # NOT suppressed: different package, no entry
            _make_vuln("CVE-OTHER", affected_package="boto3", affected_version="1.0.0", severity=Severity.MEDIUM),
        ]
        allowlist = [
            AllowlistEntry(id="CVE-KNOWN"),
            AllowlistEntry(package="pillow", severity=Severity.MEDIUM),
        ]
        blocking, allowed = filter_allowed(vulns, allowlist)
        assert len(allowed) == 2
        assert {v.id for v in allowed} == {"CVE-KNOWN", "CVE-LOW"}
        assert len(blocking) == 2
        assert {v.id for v in blocking} == {"CVE-HIGH", "CVE-OTHER"}
