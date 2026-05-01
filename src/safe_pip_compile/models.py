from __future__ import annotations
from dataclasses import dataclass, field
from datetime import date
from enum import Enum
from typing import Optional


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
    id: str
    reason: str = ""
    expires: Optional[date] = None

    def is_expired(self, today: Optional[date] = None) -> bool:
        if self.expires is None:
            return False
        return (today or date.today()) > self.expires


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
