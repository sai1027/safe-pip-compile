from __future__ import annotations

from typing import Optional

from safe_pip_compile.cache import VulnCache
from safe_pip_compile.models import ResolvedPackage, Vulnerability
from safe_pip_compile.osv_client import OSVClient


class CachedOSVClient:
    """Wraps OSVClient with a local SQLite cache layer.

    For each package+version:
    1. Check local cache first
    2. On cache miss → query OSV.dev → store results
    3. No-fix vulns are never cached (re-checked every run)
    """

    def __init__(
        self,
        osv_client: OSVClient,
        cache: VulnCache,
        reporter: Optional[object] = None,
    ):
        self._osv = osv_client
        self._cache = cache
        self._reporter = reporter
        self._cache_hits = 0
        self._cache_misses = 0

    def close(self):
        self._osv.close()
        self._cache.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def batch_query_and_fetch(
        self, packages: list[ResolvedPackage]
    ) -> list[Vulnerability]:
        """Query for vulnerabilities, using cache where possible.

        Returns the full list of Vulnerability objects (combines
        cached results with fresh OSV.dev fetches).
        """
        all_vulns: list[Vulnerability] = []
        uncached_packages: list[ResolvedPackage] = []

        for pkg in packages:
            cached = self._cache.lookup(pkg.name, pkg.version)
            if cached is not None:
                self._cache_hits += 1
                all_vulns.extend(cached)
            else:
                self._cache_misses += 1
                uncached_packages.append(pkg)

        if not uncached_packages:
            return all_vulns

        vuln_map = self._osv.batch_query(uncached_packages)

        clean_packages = [
            pkg for pkg in uncached_packages
            if pkg.name not in vuln_map
        ]
        for pkg in clean_packages:
            self._cache.store(pkg.name, pkg.version, [])

        if not vuln_map:
            return all_vulns

        all_vuln_ids = list({
            vid for ids in vuln_map.values() for vid in ids
        })

        fetched_vulns = self._osv.fetch_vulnerabilities(all_vuln_ids)

        vuln_by_id = {v.id: v for v in fetched_vulns}

        for pkg_name, vuln_ids in vuln_map.items():
            pkg_vulns: list[Vulnerability] = []
            pkg_version = next(
                (p.version for p in uncached_packages
                 if p.name == pkg_name),
                "",
            )

            for vid in vuln_ids:
                v = vuln_by_id.get(vid)
                if not v:
                    continue

                if not v.affected_package or v.affected_package.lower().replace("_", "-") != pkg_name.lower().replace("_", "-"):
                    v = Vulnerability(
                        id=v.id,
                        aliases=v.aliases,
                        summary=v.summary,
                        severity=v.severity,
                        cvss_score=v.cvss_score,
                        affected_package=pkg_name,
                        affected_version=pkg_version,
                        fixed_versions=v.fixed_versions,
                        details_url=v.details_url,
                    )

                pkg_vulns.append(v)

            self._cache.store(pkg_name, pkg_version, pkg_vulns)
            all_vulns.extend(pkg_vulns)

        return all_vulns

    @property
    def cache_hits(self) -> int:
        return self._cache_hits

    @property
    def cache_misses(self) -> int:
        return self._cache_misses
