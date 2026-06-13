# Quick Start

Get safe dependency pinning working in under 2 minutes.

---

## 1. Install

```bash
pip install safe-pip-compile
```

---

## 2. Create a `requirements.in`

List your top-level dependencies (unpinned):

```txt title="requirements.in"
django
requests
celery
```

---

## 3. Run

```bash
safe-pip-compile requirements.in -o requirements.txt
```

`safe-pip-compile` will:

1. Run `pip-compile` to resolve the full dependency tree
2. Query [OSV.dev](https://osv.dev) to check each resolved package for CVEs
3. Add version constraints to exclude vulnerable versions
4. Re-run `pip-compile` with those constraints
5. Repeat until the result is clean or the iteration limit is hit
6. Write the final `requirements.txt`

---

## 4. Example output

```
Iteration 1/10 ──────────────────────────────────────────────
  ✔ pip-compile resolved 42 packages
  ⚠  requests 2.28.0  →  CVE-2023-32681 (high)
  ⚠  django 3.2.18    →  CVE-2023-24580 (medium)
  Adding constraints: requests>=2.31.0, django>=3.2.19

Iteration 2/10 ──────────────────────────────────────────────
  ✔ pip-compile resolved 42 packages
  ✔ No blocking CVEs found

✔ requirements.txt written (clean)
```

---

## 5. Use in CI

Add this step to your GitHub Actions workflow:

```yaml
- name: Compile safe requirements
  run: |
    pip install safe-pip-compile
    safe-pip-compile requirements.in --strict
```

Exit code `1` is returned if unresolved CVEs remain, failing the CI job automatically.

---

## Flag quick reference

All flags at a glance — click any flag to go to its full documentation.

### Core resolution

| Flag | Default | Description |
|------|---------|-------------|
| [`--min-severity`](cve-filtering.md#--min-severity) | `low` | Minimum CVE severity to block. One of: `critical`, `high`, `medium`, `low` |
| [`--strict / --no-strict`](cve-filtering.md#--strict----no-strict) | `--strict` | Exit with code `1` if unresolved CVEs remain |
| [`--no-cve`](cve-filtering.md#--no-cve) | off | Skip CVE checking — pure `pip-compile` pass-through |
| [`--max-iterations`](cve-filtering.md#--max-iterations) | `10` | Maximum compile/audit loops before stopping |
| [`--allow-list PATH`](allowlist.md#--allow-list) | *(none)* | Path to a YAML file of accepted CVEs to skip |

### Output & reporting

| Flag | Default | Description |
|------|---------|-------------|
| [`-o, --output-file PATH`](output-reporting.md#--output-file---o) | `requirements.txt` | Path to write the compiled output |
| [`--dry-run`](output-reporting.md#--dry-run) | off | Preview actions without writing any output files |
| [`--json-report PATH`](output-reporting.md#--json-report) | *(none)* | Write a machine-readable JSON vulnerability report |
| [`-v, --verbose`](output-reporting.md#--verbose---v) | quiet | Increase output detail (`-v` or `-vv`) |

### Cache

| Flag | Default | Description |
|------|---------|-------------|
| [`--no-cache`](cache.md#--no-cache) | off | Bypass local cache — always query OSV.dev live |
| [`--refresh-cache`](cache.md#--refresh-cache) | off | Clear all cached data and re-fetch from OSV.dev |
| [`--clear-cache`](cache.md#--clear-cache) | off | Delete the entire cache directory and exit |

### Network & SSL

| Flag | Default | Description |
|------|---------|-------------|
| [`--cert PATH`](network-ssl.md#--cert) | *(auto)* | CA bundle for SSL verification (corporate proxies) |

---

## Next steps

- [Configuration](configuration.md) — set project defaults in `pyproject.toml`
- [CVE Allowlist](allowlist.md) — accept specific known CVEs with expiry dates
- [Exit Codes](exit-codes.md) — integrate with CI pipelines
