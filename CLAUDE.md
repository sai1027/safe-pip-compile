# safe-pip-compile

CVE-aware `pip-compile` wrapper. Iteratively resolves Python dependencies while avoiding packages with known vulnerabilities using the OSV.dev API.

## Project layout

```
src/safe_pip_compile/
  cli.py           # Click CLI entry point, flag parsing, exit codes
  core.py          # Iterative compile→audit→constrain loop (the main algorithm)
  pip_compile.py   # Subprocess wrapper around pip-compile
  parser.py        # requirements.txt parser (handles hashes, extras, continuations)
  osv_client.py    # OSV.dev batch + detail API client (httpx, parallel fetches)
  severity.py      # CVSS v2/v3/v4 vector parsing, score-to-severity mapping
  constraints.py   # Converts CVE data into pip constraint lines, merges per-package
  allowlist.py     # YAML allowlist loader and CVE matching (primary ID + aliases)
  models.py        # Dataclasses: ResolvedPackage, Vulnerability, Severity enum, etc.
  reporter.py      # Rich terminal output (tables, progress, JSON report)
  config.py        # pyproject.toml [tool.safe-pip-compile] loader
  cache.py          # SQLite+WAL local CVE cache (platformdirs, 6-month TTL)
  cached_client.py   # Cache-first wrapper around OSVClient
  exceptions.py      # Exception hierarchy
tests/               # pytest suite (61 tests), fixtures in tests/fixtures/
```

## How it works

1. Run `pip-compile` on user's `requirements.in`
2. Parse the output → list of (package, version)
3. Check local SQLite cache for each package+version → on miss, query OSV.dev
4. Filter by `--min-severity` and `--allow-list`
5. Generate exclusion constraints (e.g. `django>=3.2.25`) → re-run pip-compile with `-c`
6. Repeat until clean, stuck, or max iterations reached

## CVE cache

- SQLite with WAL mode at `~/.cache/safe-pip-compile/cache.db` (via platformdirs)
- 6-month TTL — CVE data for a specific version is stable
- Only caches vulns with fix versions; no-fix vulns are always re-checked
- Works across virtualenvs (stored in user cache dir)
- `--no-cache` disables, `--refresh-cache` wipes and re-fetches

## Development

```bash
pip install -e ".[dev]"    # install with dev deps
python -m pytest tests/ -v # run tests
```

## Key dependencies

click, httpx, pyyaml, packaging, platformdirs, rich, pip-tools

## Config precedence

Built-in defaults → `pyproject.toml` `[tool.safe-pip-compile]` → CLI flags

## Exit codes

0 = clean, 1 = unresolved CVEs (strict), 2 = pip-compile failed, 3 = network/config error
