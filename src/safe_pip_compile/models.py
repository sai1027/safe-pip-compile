from __future__ import annotations
from dataclasses import dataclass, field
from datetime import date
from enum import Enum
from typing import Optional

from packaging.specifiers import InvalidSpecifier, SpecifierSet


class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    UNKNOWN = 0

    def meets_threshold(self, threshold: Severity) -> bool:
        if self == Severity.UNKNOWN:
            return True
        return self.value >= threshold.value

    @classmethod
    def from_string(cls, value: str) -> Severity:
        try:
            return cls[value.upper()]
        except KeyError:
            return cls.UNKNOWN


class CompileStatus(Enum):
    CLEAN = "clean"
    UNFIXABLE_CVES = "unfixable_cves"
    STUCK = "stuck"
    MAX_ITERATIONS = "max_iterations"
    PIP_COMPILE_FAILED = "pip_compile_failed"


@dataclass(frozen=True)
class ResolvedPackage:
    name: str
    version: str
    extras: tuple[str, ...] = ()

    @property
    def normalized_name(self) -> str:
        return self.name.lower().replace("_", "-")


@dataclass(frozen=True)
class Vulnerability:
    id: str
    aliases: tuple[str, ...] = ()
    summary: str = ""
    severity: Severity = Severity.UNKNOWN
    cvss_score: Optional[float] = None
    affected_package: str = ""
    affected_version: str = ""
    fixed_versions: tuple[str, ...] = ()
    details_url: str = ""

    @property
    def display_id(self) -> str:
        for alias in self.aliases:
            if alias.startswith("CVE-"):
                return alias
        return self.id


@dataclass(frozen=True)
class AllowlistEntry:
    """A single entry in the CVE allowlist.

    An entry must have at least one of `id` or `package`.

    - `id`       : suppress a specific CVE/GHSA by its ID or alias.
    - `package`  : suppress CVEs by library name, with optional version specifiers
                   and a per-package severity cap.

    When both `id` and `package` are set, the CVE-id match is tried first (and
    always wins), then the package-based match is tried as a fallback.
    """

    # CVE / GHSA identifier (optional when `package` is set)
    id: str = ""
    # Library name (optional when `id` is set)
    package: str = ""
    # PEP 440 version specifiers, e.g. (">=2.0", "<3.0"). Empty = all versions.
    versions: tuple[str, ...] = ()
    # Severity cap: suppress CVEs at or below this level. None = suppress all.
    severity: Optional["Severity"] = None
    reason: str = ""
    expires: Optional[date] = None

    def is_expired(self, today: Optional[date] = None) -> bool:
        if self.expires is None:
            return False
        return (today or date.today()) > self.expires

    def matches_package(self, pkg_name: str, pkg_version: str) -> bool:
        """Return True if this package-based entry applies to the given package/version.

        Checks:
        1. Package name matches (PEP 503 normalised: lowercase, - and _ equivalent).
        2. Version satisfies all specifiers in `versions` (empty = wildcard).
        3. Does NOT check severity or expiry — callers handle those separately.
        """
        if not self.package:
            return False

        def _norm(name: str) -> str:
            return name.lower().replace("_", "-")

        if _norm(self.package) != _norm(pkg_name):
            return False

        if self.versions:
            try:
                spec = SpecifierSet(",".join(self.versions))
                if not spec.contains(pkg_version, prereleases=True):
                    return False
            except InvalidSpecifier:
                # Invalid specifiers are rejected at load time; this is a safety fallback.
                return False

        return True


@dataclass(frozen=True)
class PinnedBlockingPackage:
    """A package pinned with == in a source file that has blocking CVEs with available fixes."""

    name: str
    version: str
    vuln_ids: tuple[str, ...]
    fix_versions: tuple[str, ...]
    severity: Severity


@dataclass
class IterationResult:
    iteration: int
    packages: list[ResolvedPackage] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    filtered_vulns: list[Vulnerability] = field(default_factory=list)
    constraints_added: list[str] = field(default_factory=list)
    pip_compile_succeeded: bool = True


@dataclass
class CompileResult:
    status: CompileStatus
    iterations: list[IterationResult] = field(default_factory=list)
    final_packages: list[ResolvedPackage] = field(default_factory=list)
    remaining_vulns: list[Vulnerability] = field(default_factory=list)
    all_vulns_found: list[Vulnerability] = field(default_factory=list)
