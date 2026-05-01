import json

import httpx
import pytest
import respx

from safe_pip_compile.exceptions import OSVAPIError, OSVNetworkError
from safe_pip_compile.models import ResolvedPackage, Severity
from safe_pip_compile.osv_client import OSVClient


@pytest.fixture
def osv_client():
    client = OSVClient()
    yield client
    client.close()


@respx.mock
def test_batch_query_finds_vulns(osv_client, sample_osv_batch_path):
    with open(sample_osv_batch_path) as f:
        batch_response = json.load(f)

    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(200, json=batch_response)
    )

    packages = [
        ResolvedPackage(name="asgiref", version="3.7.2"),
        ResolvedPackage(name="certifi", version="2023.7.22"),
        ResolvedPackage(name="charset-normalizer", version="3.3.2"),
        ResolvedPackage(name="django", version="3.2.1"),
        ResolvedPackage(name="idna", version="3.6"),
        ResolvedPackage(name="requests", version="2.28.0"),
        ResolvedPackage(name="sqlparse", version="0.4.4"),
        ResolvedPackage(name="urllib3", version="1.26.15"),
    ]

    result = osv_client.batch_query(packages)
    assert "django" in result
    assert "GHSA-qrw5-5h28-modded" in result["django"]
    assert "PYSEC-2024-0001" in result["django"]
    assert "requests" in result
    assert "urllib3" in result


@respx.mock
def test_batch_query_no_vulns(osv_client):
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(200, json={"results": [{"vulns": []}]})
    )

    packages = [ResolvedPackage(name="safe-package", version="1.0.0")]
    result = osv_client.batch_query(packages)
    assert result == {}


@respx.mock
def test_batch_query_api_error(osv_client):
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(500, text="Internal Server Error")
    )

    with pytest.raises(OSVAPIError):
        osv_client.batch_query([ResolvedPackage(name="django", version="3.2.1")])


@respx.mock
def test_fetch_vulnerability(osv_client, sample_osv_vuln_path):
    with open(sample_osv_vuln_path) as f:
        vuln_response = json.load(f)

    respx.get("https://api.osv.dev/v1/vulns/GHSA-qrw5-5h28-modded").mock(
        return_value=httpx.Response(200, json=vuln_response)
    )

    vuln = osv_client.fetch_vulnerability("GHSA-qrw5-5h28-modded")
    assert vuln.id == "GHSA-qrw5-5h28-modded"
    assert "CVE-2024-12345" in vuln.aliases
    assert vuln.severity == Severity.CRITICAL
    assert "3.2.25" in vuln.fixed_versions
    assert vuln.affected_package == "django"


@respx.mock
def test_fetch_vulnerabilities_parallel(osv_client):
    vuln1 = {
        "id": "V1",
        "aliases": [],
        "summary": "vuln 1",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [{"package": {"name": "pkg1", "ecosystem": "PyPI"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "2.0"}]}]}],
    }
    vuln2 = {
        "id": "V2",
        "aliases": ["CVE-2024-00002"],
        "summary": "vuln 2",
        "affected": [{"package": {"name": "pkg2", "ecosystem": "PyPI"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "3.0"}]}]}],
    }

    respx.get("https://api.osv.dev/v1/vulns/V1").mock(
        return_value=httpx.Response(200, json=vuln1)
    )
    respx.get("https://api.osv.dev/v1/vulns/V2").mock(
        return_value=httpx.Response(200, json=vuln2)
    )

    vulns = osv_client.fetch_vulnerabilities(["V1", "V2"])
    assert len(vulns) == 2
    ids = {v.id for v in vulns}
    assert "V1" in ids
    assert "V2" in ids


def test_batch_query_empty_list(osv_client):
    result = osv_client.batch_query([])
    assert result == {}
