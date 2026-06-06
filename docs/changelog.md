# Changelog

All notable changes to `safe-pip-compile` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.8] — Latest

### Added
- `--no-cve` flag to skip CVE checking entirely and use `safe-pip-compile` as a pure `pip-compile` pass-through
- Dependency resolution cache: `pip-compile` results are cached for 30 minutes, skipping re-resolution when inputs haven't changed — saves 30–120 s on complex dependency sets

### Fixed
- Improved handling of packages with no OSV entries (no longer treated as errors)

---

## [0.1.7]

### Added
- `--refresh-cache` flag: clears all cached CVE rows and re-fetches from OSV.dev before running
- `--clear-cache` flag: deletes the entire cache directory and exits (useful before uninstalling)
- SQLite WAL mode for concurrent cache access

### Changed
- Unfixed vulnerabilities are no longer cached permanently so newly published fixes are picked up automatically

---

## [0.1.6]

### Added
- Local SQLite CVE cache powered by `platformdirs` — cached data is per-user and persists across virtual environments
- `--no-cache` flag to disable the cache for a single run

---

## [0.1.5]

### Added
- `--json-report PATH` flag to write a machine-readable JSON vulnerability report
- CVE allowlist expiry: entries with an `expires` date are automatically ignored after that date

---

## [0.1.4]

### Added
- CVE allowlist support (`--allow-list PATH`) using a YAML file
- Aliases are matched: a CVE ID also matches its GHSA and PYSEC aliases

---

## [0.1.3]

### Added
- `--cert PATH` flag and environment variable fallback chain for corporate proxy / SSL inspection support

---

## [0.1.2]

### Added
- `pyproject.toml` configuration support (`[tool.safe-pip-compile]`)
- `--strict / --no-strict` flag

---

## [0.1.1]

### Added
- `--min-severity` flag (`critical`, `high`, `medium`, `low`)
- `--dry-run` flag

---

## [0.1.0] — Initial release

### Added
- Core iterative compile/audit loop using OSV.dev Batch API
- `pip-compile` pass-through for unknown flags (via `--`)
- Exit codes: 0 (clean), 1 (CVEs remain), 2 (resolver failure), 3 (network error)
