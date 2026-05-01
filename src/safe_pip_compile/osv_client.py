from __future__ import annotations

import os
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import httpx
from packaging.version import Version

from safe_pip_compile.exceptions import OSVAPIError, OSVNetworkError
from safe_pip_compile.models import ResolvedPackage, Severity, Vulnerability
from safe_pip_compile.severity import extract_severity_from_osv


def _resolve_ssl_cert() -> Union[str, bool, None]:
    """Find a CA bundle from environment variables.

    Checks SSL_CERT_FILE, REQUESTS_CA_BUNDLE, and CURL_CA_BUNDLE
    (same env vars that pip, requests, and httpx respect).
    """
    for var in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        path = os.environ.get(var)
        if path and os.path.isfile(path):
            return path
    return None


class OSVClient:
    BASE_URL = "https://api.osv.dev"
    BATCH_ENDPOINT = "/v1/querybatch"
    VULN_ENDPOINT = "/v1/vulns/{vuln_id}"
    BATCH_SIZE = 1000
    MAX_WORKERS = 10

    def __init__(
        self,
        http_client: Optional[httpx.Client] = None,
        cert_path: Optional[str] = None,
    ):
        if http_client:
            self._client = http_client
        else:
            ssl_context = ssl.create_default_context()  
            resolved = cert_path or _resolve_ssl_cert()
            if resolved:
                ssl_context.load_verify_locations(resolved)

            self._client = httpx.Client(
                timeout=30.0,
                verify=ssl_context,
                transport=httpx.HTTPTransport(retries=3),
            )

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def batch_query(
        self, packages: list[ResolvedPackage]
    ) -> dict[str, list[str]]:
        """Query OSV for all packages. Returns {package_name: [vuln_id, ...]}."""
        if not packages:
            return {}

        all_results: dict[str, list[str]] = {}

        for batch_start in range(0, len(packages), self.BATCH_SIZE):
            batch = packages[batch_start : batch_start + self.BATCH_SIZE]
            queries = [
                {
                    "package": {"name": pkg.name, "ecosystem": "PyPI"},
                    "version": pkg.version,
                }
                for pkg in batch
            ]

            try:
                resp = self._client.post(
                    f"{self.BASE_URL}{self.BATCH_ENDPOINT}",
                    json={"queries": queries},
                )
            except httpx.ConnectError as e:
                raise OSVNetworkError(f"Cannot reach OSV.dev API: {e}") from e
            except httpx.TimeoutException as e:
                raise OSVNetworkError(f"OSV.dev API timeout: {e}") from e

            if resp.status_code != 200:
                raise OSVAPIError(resp.status_code, resp.text)

            data = resp.json()
            results = data.get("results", [])

            for i, result in enumerate(results):
                vulns = result.get("vulns", [])
                if vulns:
                    pkg = batch[i]
                    vuln_ids = [v["id"] for v in vulns if "id" in v]
                    if vuln_ids:
                        all_results.setdefault(pkg.name, []).extend(vuln_ids)

        for name in all_results:
            all_results[name] = list(set(all_results[name]))

        return all_results

    def fetch_vulnerability(self, vuln_id: str) -> Vulnerability:
        """Fetch full details for a single vulnerability."""
        url = f"{self.BASE_URL}{self.VULN_ENDPOINT}".format(vuln_id=vuln_id)

        try:
            resp = self._client.get(url)
        except httpx.ConnectError as e:
            raise OSVNetworkError(f"Cannot reach OSV.dev API: {e}") from e
        except httpx.TimeoutException as e:
            raise OSVNetworkError(f"OSV.dev API timeout: {e}") from e

        if resp.status_code != 200:
            raise OSVAPIError(resp.status_code, resp.text)

        return self._parse_vulnerability(resp.json())

    def fetch_vulnerabilities(self, vuln_ids: list[str]) -> list[Vulnerability]:
        """Fetch details for multiple vulnerabilities in parallel."""
        unique_ids = list(set(vuln_ids))
        results: list[Vulnerability] = []
        errors: list[str] = []

        with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as pool:
            future_to_id = {
                pool.submit(self.fetch_vulnerability, vid): vid
                for vid in unique_ids
            }

            for future in as_completed(future_to_id):
                vid = future_to_id[future]
                try:
                    results.append(future.result())
                except Exception as e:
                    errors.append(f"{vid}: {e}")

        if errors and not results:
            raise OSVAPIError(0, f"All vulnerability fetches failed: {'; '.join(errors)}")

        return results

    def _parse_vulnerability(self, data: dict) -> Vulnerability:
        vuln_id = data.get("id", "")
        aliases = tuple(data.get("aliases", []))
        summary = data.get("summary", data.get("details", ""))[:200]
        severity, cvss_score = extract_severity_from_osv(data)

        affected_packages: list[str] = []
        fixed_versions: list[str] = []

        for affected in data.get("affected", []):
            pkg_info = affected.get("package", {})
            if pkg_info.get("ecosystem") == "PyPI":
                affected_packages.append(pkg_info.get("name", ""))

                for rng in affected.get("ranges", []):
                    if rng.get("type") == "ECOSYSTEM":
                        for event in rng.get("events", []):
                            fixed = event.get("fixed")
                            if fixed:
                                fixed_versions.append(fixed)

        fixed_versions = _sort_versions(list(set(fixed_versions)))

        details_url = ""
        for ref in data.get("references", []):
            if ref.get("type") == "ADVISORY":
                details_url = ref.get("url", "")
                break
        if not details_url:
            details_url = f"https://osv.dev/vulnerability/{vuln_id}"

        return Vulnerability(
            id=vuln_id,
            aliases=aliases,
            summary=summary,
            severity=severity,
            cvss_score=cvss_score,
            affected_package=affected_packages[0] if affected_packages else "",
            fixed_versions=tuple(fixed_versions),
            details_url=details_url,
        )


def _sort_versions(versions: list[str]) -> list[str]:
    parsed = []
    for v in versions:
        try:
            parsed.append((Version(v), v))
        except Exception:
            parsed.append((Version("0"), v))
    parsed.sort(key=lambda x: x[0])
    return [v for _, v in parsed]
