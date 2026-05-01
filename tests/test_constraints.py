from safe_pip_compile.constraints import (
    generate_constraints,
    merge_constraints,
)
from safe_pip_compile.models import ResolvedPackage, Severity, Vulnerability


def _make_vuln(pkg, version, fixed=(), vuln_id="TEST-001"):
    return Vulnerability(
        id=vuln_id,
        affected_package=pkg,
        affected_version=version,
        fixed_versions=tuple(fixed),
        severity=Severity.HIGH,
    )


def _make_pkg(name, version):
    return ResolvedPackage(name=name, version=version)


def test_generate_with_fix_version():
    vulns = [_make_vuln("django", "3.2.1", fixed=["3.2.25"])]
    pkgs = [_make_pkg("django", "3.2.1")]

    constraints = generate_constraints(vulns, pkgs)
    assert constraints == ["django>=3.2.25"]


def test_generate_without_fix_version():
    vulns = [_make_vuln("django", "3.2.1", fixed=[])]
    pkgs = [_make_pkg("django", "3.2.1")]

    constraints = generate_constraints(vulns, pkgs)
    assert constraints == ["django!=3.2.1"]


def test_generate_multiple_vulns_same_package():
    vulns = [
        _make_vuln("django", "3.2.1", fixed=["3.2.8"], vuln_id="V1"),
        _make_vuln("django", "3.2.1", fixed=["3.2.10"], vuln_id="V2"),
    ]
    pkgs = [_make_pkg("django", "3.2.1")]

    constraints = generate_constraints(vulns, pkgs)
    assert constraints == ["django>=3.2.10"]


def test_generate_multiple_packages():
    vulns = [
        _make_vuln("django", "3.2.1", fixed=["3.2.25"]),
        _make_vuln("requests", "2.28.0", fixed=["2.31.0"]),
    ]
    pkgs = [_make_pkg("django", "3.2.1"), _make_pkg("requests", "2.28.0")]

    constraints = generate_constraints(vulns, pkgs)
    assert "django>=3.2.25" in constraints
    assert "requests>=2.31.0" in constraints


def test_generate_no_matching_package():
    vulns = [_make_vuln("nonexistent", "1.0.0", fixed=["1.0.1"])]
    pkgs = [_make_pkg("django", "3.2.1")]

    constraints = generate_constraints(vulns, pkgs)
    assert constraints == []


def test_merge_constraints_takes_stricter():
    existing = ["django>=3.2.8"]
    new = ["django>=3.2.10"]

    merged = merge_constraints(existing, new)
    assert merged == ["django>=3.2.10"]


def test_merge_constraints_different_packages():
    existing = ["django>=3.2.8"]
    new = ["requests>=2.31.0"]

    merged = merge_constraints(existing, new)
    assert "django>=3.2.8" in merged
    assert "requests>=2.31.0" in merged


def test_merge_ge_over_ne():
    existing = ["django!=3.2.1"]
    new = ["django>=3.2.25"]

    merged = merge_constraints(existing, new)
    assert merged == ["django>=3.2.25"]
