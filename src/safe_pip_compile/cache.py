from __future__ import annotations

import json
import os
import sqlite3
import time
from typing import Optional

from platformdirs import user_cache_path

from safe_pip_compile.models import Severity, Vulnerability

SCHEMA_VERSION = 1
DEFAULT_TTL_SECONDS = 6 * 30 * 24 * 3600  # ~6 months


def get_cache_dir() -> str:
    return str(user_cache_path("safe-pip-compile", appauthor=False, ensure_exists=True))


def get_cache_db_path() -> str:
    return os.path.join(get_cache_dir(), "cache.db")


class VulnCache:
    def __init__(
        self,
        db_path: Optional[str] = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ):
        self._db_path = db_path or get_cache_db_path()
        self._ttl = ttl_seconds
        self._conn: Optional[sqlite3.Connection] = None

    def open(self):
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        self._conn = sqlite3.connect(self._db_path, timeout=5)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()
        return self

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()

    def _init_schema(self):
        c = self._conn
        c.execute("""
            CREATE TABLE IF NOT EXISTS cache_meta (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)

        stored_version = None
        row = c.execute(
            "SELECT value FROM cache_meta WHERE key = 'schema_version'"
        ).fetchone()
        if row:
            stored_version = int(row[0])

        if stored_version is not None and stored_version != SCHEMA_VERSION:
            c.execute("DROP TABLE IF EXISTS vulnerabilities")
            c.execute("DELETE FROM cache_meta")

        c.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                package TEXT NOT NULL,
                version TEXT NOT NULL,
                cve_id TEXT NOT NULL,
                aliases TEXT DEFAULT '[]',
                summary TEXT DEFAULT '',
                severity TEXT DEFAULT 'UNKNOWN',
                cvss_score REAL,
                fix_versions TEXT DEFAULT '[]',
                details_url TEXT DEFAULT '',
                fetched_at REAL NOT NULL,
                PRIMARY KEY (package, version, cve_id)
            )
        """)
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_vuln_pkg_ver
            ON vulnerabilities(package, version)
        """)
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_vuln_fetched
            ON vulnerabilities(fetched_at)
        """)

        # Track which (package, version) pairs have been fully queried
        c.execute("""
            CREATE TABLE IF NOT EXISTS queried_packages (
                package TEXT NOT NULL,
                version TEXT NOT NULL,
                fetched_at REAL NOT NULL,
                vuln_count INTEGER DEFAULT 0,
                PRIMARY KEY (package, version)
            )
        """)

        c.execute(
            "INSERT OR REPLACE INTO cache_meta (key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        c.commit()

    def lookup(
        self, package: str, version: str
    ) -> Optional[list[Vulnerability]]:
        """Look up cached vulns for a package+version.

        Returns None on cache miss (never queried or expired).
        Returns [] if queried and no cacheable vulns were found.
        Returns list of Vulnerability on cache hit.
        """
        if not self._conn:
            return None

        now = time.time()
        cutoff = now - self._ttl
        package = package.lower().replace("_", "-")

        row = self._conn.execute(
            "SELECT fetched_at, vuln_count FROM queried_packages "
            "WHERE package = ? AND version = ?",
            (package, version),
        ).fetchone()

        if not row or row[0] < cutoff:
            return None

        if row[1] == 0:
            return []

        rows = self._conn.execute(
            "SELECT cve_id, aliases, summary, severity, cvss_score, "
            "fix_versions, details_url "
            "FROM vulnerabilities "
            "WHERE package = ? AND version = ?",
            (package, version),
        ).fetchall()

        vulns = []
        for r in rows:
            vulns.append(Vulnerability(
                id=r[0],
                aliases=tuple(json.loads(r[1])),
                summary=r[2],
                severity=Severity.from_string(r[3]),
                cvss_score=r[4],
                affected_package=package,
                affected_version=version,
                fixed_versions=tuple(json.loads(r[5])),
                details_url=r[6],
            ))

        return vulns

    def store(
        self, package: str, version: str, vulns: list[Vulnerability]
    ):
        """Store vulnerability results for a package+version.

        Only caches vulns that have fix versions (no-fix vulns are skipped
        so they get re-checked on future runs).
        """
        if not self._conn:
            return

        now = time.time()
        package = package.lower().replace("_", "-")

        cacheable = [v for v in vulns if v.fixed_versions]

        self._conn.execute(
            "INSERT OR REPLACE INTO queried_packages "
            "(package, version, fetched_at, vuln_count) VALUES (?, ?, ?, ?)",
            (package, version, now, len(cacheable)),
        )

        self._conn.execute(
            "DELETE FROM vulnerabilities WHERE package = ? AND version = ?",
            (package, version),
        )

        for v in cacheable:
            self._conn.execute(
                "INSERT OR REPLACE INTO vulnerabilities "
                "(package, version, cve_id, aliases, summary, severity, "
                "cvss_score, fix_versions, details_url, fetched_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    package,
                    version,
                    v.id,
                    json.dumps(list(v.aliases)),
                    v.summary,
                    v.severity.name,
                    v.cvss_score,
                    json.dumps(list(v.fixed_versions)),
                    v.details_url,
                    now,
                ),
            )

        self._conn.commit()

    def purge_expired(self):
        """Remove entries older than TTL."""
        if not self._conn:
            return

        cutoff = time.time() - self._ttl
        self._conn.execute(
            "DELETE FROM vulnerabilities WHERE fetched_at < ?", (cutoff,)
        )
        self._conn.execute(
            "DELETE FROM queried_packages WHERE fetched_at < ?", (cutoff,)
        )
        self._conn.commit()

    def clear(self):
        """Wipe the entire cache."""
        if not self._conn:
            return

        self._conn.execute("DELETE FROM vulnerabilities")
        self._conn.execute("DELETE FROM queried_packages")
        self._conn.commit()

    def stats(self) -> dict:
        """Return cache statistics."""
        if not self._conn:
            return {"packages": 0, "vulnerabilities": 0}

        pkg_count = self._conn.execute(
            "SELECT COUNT(*) FROM queried_packages"
        ).fetchone()[0]
        vuln_count = self._conn.execute(
            "SELECT COUNT(*) FROM vulnerabilities"
        ).fetchone()[0]

        return {"packages": pkg_count, "vulnerabilities": vuln_count}
