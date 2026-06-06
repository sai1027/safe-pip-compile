# Configuration

Every CLI flag can be set as a project-level default in `pyproject.toml` under the `[tool.safe-pip-compile]` section.

**CLI flags always take precedence over file settings.**

---

## Full example

```toml title="pyproject.toml"
[tool.safe-pip-compile]
# ── Core resolution ────────────────────────────────────────
max-iterations = 10          # Maximum compile/audit loops (default: 10)
min-severity   = "high"      # Minimum blocking severity: critical/high/medium/low
allowlist      = "cve-allowlist.yaml"  # Path to CVE allowlist YAML
strict         = true        # Fail on unresolved CVEs (default: true)

# ── Output / reporting ─────────────────────────────────────
output-file  = "requirements.txt"   # Default output file (-o)
json-report  = "audit.json"         # Write JSON vulnerability report
dry-run      = false                # Preview without writing files

# ── Network / SSL ──────────────────────────────────────────
cert = "/etc/ssl/certs/corporate-ca.pem"  # CA bundle path (--cert)

# ── Cache ──────────────────────────────────────────────────
no-cache      = false   # Always query OSV.dev, skip local cache
refresh-cache = false   # Clear cache before run

# ── Verbosity ──────────────────────────────────────────────
verbose = 1             # 0 = quiet, 1 = -v, 2 = -vv
```

---

## Option reference

| `pyproject.toml` key | CLI equivalent | Type | Default |
|---|---|---|---|
| `max-iterations` | `--max-iterations INT` | integer | `10` |
| `min-severity` | `--min-severity LEVEL` | string | `"low"` |
| `allowlist` | `--allow-list PATH` | string | `""` |
| `strict` | `--strict / --no-strict` | boolean | `true` |
| `output-file` | `-o / --output-file PATH` | string | `"requirements.txt"` |
| `json-report` | `--json-report PATH` | string | `""` |
| `dry-run` | `--dry-run` | boolean | `false` |
| `cert` | `--cert PATH` | string | `""` |
| `no-cache` | `--no-cache` | boolean | `false` |
| `refresh-cache` | `--refresh-cache` | boolean | `false` |
| `verbose` | `-v` / `-vv` | integer | `0` |

---

## Minimal recommended setup

For most projects, a minimal config is enough:

```toml title="pyproject.toml"
[tool.safe-pip-compile]
min-severity = "high"
strict       = true
```

This blocks only high and critical CVEs and fails CI if any remain unresolved.

---

## Precedence

```
CLI flag  >  pyproject.toml  >  built-in default
```

For example, `--min-severity critical` on the command line will override `min-severity = "high"` in `pyproject.toml`.
