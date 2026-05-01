import os
import time

import pytest

from safe_pip_compile.cache import VulnCache
from safe_pip_compile.models import Severity, Vulnerability


@pytest.fixture
def cache_db(tmp_path):
    db_path = str(tmp_path / "test_cache.db")
    cache = VulnCache(db_path=db_path, ttl_seconds=3600)
    cache.open()
    yield cache
    cache.close()


def _make_vuln(cve_id="CVE-2024-001", pkg="django", version="3.2.1",
               fix=("3.2.25",), severity=Severity.HIGH):
    return Vulnerability(
        id=cve_id,
        aliases=("GHSA-test",),
        summary="Test vuln",
        severity=severity,
        cvss_score=7.5,
        affected_package=pkg,
        affected_version=version,
        fixed_versions=fix,
        details_url="https://osv.dev/vulnerability/CVE-2024-001",
    )


def test_store_and_lookup(cache_db):
    vuln = _make_vuln()
    cache_db.store("django", "3.2.1", [vuln])

    result = cache_db.lookup("django", "3.2.1")
    assert result is not None
    assert len(result) == 1
    assert result[0].id == "CVE-2024-001"
    assert result[0].severity == Severity.HIGH
    assert result[0].fixed_versions == ("3.2.25",)


def test_cache_miss(cache_db):
    result = cache_db.lookup("nonexistent", "1.0.0")
    assert result is None


def test_store_clean_package(cache_db):
    cache_db.store("safe-pkg", "1.0.0", [])

    result = cache_db.lookup("safe-pkg", "1.0.0")
    assert result is not None
    assert result == []


def test_no_fix_vulns_not_cached(cache_db):
    vuln_with_fix = _make_vuln(cve_id="CVE-FIX", fix=("3.2.25",))
    vuln_no_fix = _make_vuln(cve_id="CVE-NOFIX", fix=())

    cache_db.store("django", "3.2.1", [vuln_with_fix, vuln_no_fix])

    result = cache_db.lookup("django", "3.2.1")
    assert result is not None
    assert len(result) == 1
    assert result[0].id == "CVE-FIX"


def test_ttl_expiry(tmp_path):
    db_path = str(tmp_path / "ttl_test.db")
    cache = VulnCache(db_path=db_path, ttl_seconds=1)
    cache.open()

    vuln = _make_vuln()
    cache.store("django", "3.2.1", [vuln])

    result = cache.lookup("django", "3.2.1")
    assert result is not None

    time.sleep(1.5)

    result = cache.lookup("django", "3.2.1")
    assert result is None

    cache.close()


def test_clear(cache_db):
    cache_db.store("django", "3.2.1", [_make_vuln()])
    cache_db.store("flask", "2.0.0", [])

    stats = cache_db.stats()
    assert stats["packages"] == 2

    cache_db.clear()

    stats = cache_db.stats()
    assert stats["packages"] == 0
    assert stats["vulnerabilities"] == 0


def test_purge_expired(tmp_path):
    db_path = str(tmp_path / "purge_test.db")
    cache = VulnCache(db_path=db_path, ttl_seconds=1)
    cache.open()

    cache.store("old-pkg", "1.0.0", [_make_vuln(pkg="old-pkg")])
    time.sleep(1.5)
    cache.store("new-pkg", "2.0.0", [_make_vuln(pkg="new-pkg")])

    cache.purge_expired()

    assert cache.lookup("old-pkg", "1.0.0") is None
    assert cache.lookup("new-pkg", "2.0.0") is not None

    cache.close()


def test_stats(cache_db):
    cache_db.store("django", "3.2.1", [
        _make_vuln(cve_id="CVE-1"),
        _make_vuln(cve_id="CVE-2"),
    ])
    cache_db.store("flask", "2.0.0", [])

    stats = cache_db.stats()
    assert stats["packages"] == 2
    assert stats["vulnerabilities"] == 2


def test_name_normalization(cache_db):
    vuln = _make_vuln(pkg="Django_Rest_Framework")
    cache_db.store("Django_Rest_Framework", "3.14.0", [vuln])

    result = cache_db.lookup("django-rest-framework", "3.14.0")
    assert result is not None
    assert len(result) == 1


def test_multiple_vulns_per_package(cache_db):
    vulns = [
        _make_vuln(cve_id="CVE-1", fix=("3.2.25",)),
        _make_vuln(cve_id="CVE-2", fix=("3.2.30",)),
        _make_vuln(cve_id="CVE-3", fix=("4.0.0",)),
    ]
    cache_db.store("django", "3.2.1", vulns)

    result = cache_db.lookup("django", "3.2.1")
    assert result is not None
    assert len(result) == 3
    ids = {v.id for v in result}
    assert ids == {"CVE-1", "CVE-2", "CVE-3"}


def test_update_overwrites(cache_db):
    cache_db.store("django", "3.2.1", [_make_vuln(cve_id="CVE-OLD")])
    cache_db.store("django", "3.2.1", [_make_vuln(cve_id="CVE-NEW")])

    result = cache_db.lookup("django", "3.2.1")
    assert len(result) == 1
    assert result[0].id == "CVE-NEW"


def test_different_versions_independent(cache_db):
    cache_db.store("django", "3.2.1", [_make_vuln(cve_id="CVE-OLD")])
    cache_db.store("django", "4.2.7", [])

    old = cache_db.lookup("django", "3.2.1")
    new = cache_db.lookup("django", "4.2.7")

    assert len(old) == 1
    assert new == []
