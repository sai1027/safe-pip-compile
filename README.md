# safe-pip-compile

A drop-in `pip-compile` wrapper that avoids pinning packages with known CVEs.

`pip-compile` resolves dependencies without vulnerability awareness — it will happily pin a version with critical CVEs. `safe-pip-compile` automates the compile → audit → fix loop by querying [OSV.dev](https://osv.dev) and iteratively constraining vulnerable versions out of the resolution.

## Installation

```bash
pip install -e .
```

## Quick start

```bash
# Drop-in replacement for pip-compile
safe-pip-compile requirements.in -o requirements.txt
```

## CLI flags

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output-file PATH` | Output requirements.txt path | `<input_basename>.txt` |
| `--min-severity LEVEL` | Only block CVEs at this level or above (`critical`, `high`, `medium`, `low`) | all (blocks everything) |
| `--allow-list PATH` | YAML file of accepted CVEs to skip | none |
| `--max-iterations INT` | Max compile→audit loops before giving up | `10` |
| `--strict / --no-strict` | Exit code 1 if unresolved CVEs remain | `--strict` |
| `--dry-run` | Show what would happen, write nothing | off |
| `--json-report PATH` | Write machine-readable JSON vulnerability report | none |
| `--cert PATH` | CA bundle for SSL verification (corporate proxies) | auto-detect from env |
| `--no-cache` | Disable local CVE cache, always query OSV.dev | cache enabled |
| `--refresh-cache` | Wipe cached data and re-fetch from OSV.dev | off |
| `-v, --verbose` | Increase output detail (`-v`, `-vv`) | quiet |

All other flags pass through to `pip-compile` (e.g. `--generate-hashes`, `--allow-unsafe`).

## Examples

```bash
# Only block high and critical CVEs
safe-pip-compile requirements.in --min-severity high

# Accept specific CVEs via allowlist
safe-pip-compile requirements.in --allow-list cve-allowlist.yaml

# Pass pip-compile flags through
safe-pip-compile requirements.in -- --generate-hashes --allow-unsafe

# CI: generate JSON report and fail on unresolved CVEs
safe-pip-compile requirements.in --json-report audit.json --strict

# Preview without writing files
safe-pip-compile requirements.in --dry-run -v

# Skip cache, always query OSV.dev fresh
safe-pip-compile requirements.in --no-cache

# Wipe cache and re-fetch everything
safe-pip-compile requirements.in --refresh-cache
```

## Allowlist format

Create a `cve-allowlist.yaml` to accept specific CVEs:

```yaml
allowed_cves:
  - id: CVE-2024-12345
    reason: "Not applicable — we don't use the affected feature"
    expires: 2025-06-01  # optional, re-blocks after this date

  - id: GHSA-xxxx-yyyy-zzzz
    reason: "Accepted risk, tracked in JIRA-789"
```

Matches against vuln ID and all aliases (CVE, PYSEC, GHSA).

## pyproject.toml config

```toml
[tool.safe-pip-compile]
max-iterations = 10
min-severity = "high"
allowlist = "cve-allowlist.yaml"
strict = true
```

CLI flags override these values.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean — no blocking CVEs |
| `1` | Unresolved CVEs remain (strict mode) |
| `2` | pip-compile resolution failed |
| `3` | Network or configuration error |

## How it works

```
requirements.in
     │
     ▼
┌─ LOOP (max N iterations) ──────────────────────────┐
│  1. pip-compile (with accumulated constraints)      │
│  2. Parse resolved packages                         │
│  3. Check local cache → on miss, query OSV.dev       │
│  4. Filter by severity + allowlist                  │
│  5. Generate constraints (e.g. django>=3.2.25)      │
│  6. Clean? → done. Stuck? → report. Else → loop.   │
└─────────────────────────────────────────────────────┘
     │
     ▼
requirements.txt (CVE-free)
```

## Local CVE cache

Vulnerability data is cached in a local SQLite database to avoid repeated OSV.dev API calls.

- **Location:** `~/.cache/safe-pip-compile/cache.db` (Linux), `~/Library/Caches/safe-pip-compile/cache.db` (macOS), `%LOCALAPPDATA%\safe-pip-compile\Cache\cache.db` (Windows)
- **TTL:** 6 months — "django 3.2.1 has CVE-X, fix is 3.2.25" doesn't change
- **No-fix vulns are never cached** — they get re-checked every run in case a fix is published
- **Works across virtualenvs** — stored in user cache dir, not inside any venv
- **Concurrent-safe** — SQLite WAL mode allows parallel readers

## Corporate proxy / SSL issues

If you're behind a corporate proxy that does SSL inspection, you may see:

```
OSV.dev error: Cannot reach OSV.dev API: [SSL: CERTIFICATE_VERIFY_FAILED]
```

Three ways to fix this:

**Option 1: `--cert` flag**
```bash
safe-pip-compile requirements.in --cert /path/to/corporate-ca-bundle.pem
```

**Option 2: Environment variable** (auto-detected, no flag needed)
```bash
# Set any of these — same vars that pip, requests, and httpx respect
export SSL_CERT_FILE=/path/to/corporate-ca-bundle.pem
# or
export REQUESTS_CA_BUNDLE=/path/to/corporate-ca-bundle.pem

safe-pip-compile requirements.in
```

**Option 3: Find your org's CA cert**
```bash
# Check if pip already knows where it is
python -m pip config get global.cert

# On Windows, export from certificate store:
# certmgr.msc → Trusted Root CAs → find your org's proxy cert → export as .pem
```

Lookup order: `--cert` flag > `SSL_CERT_FILE` > `REQUESTS_CA_BUNDLE` > `CURL_CA_BUNDLE` > system default.

## Development

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
```
