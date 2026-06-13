# Output & Reporting

Control where `safe-pip-compile` writes its output and how much information it shows during a run.

---

## --output-file / -o

Path to write the compiled `requirements.txt`. Both `-o` and `--output-file` are equivalent.

**Default:** `requirements.txt`

**CLI:**

```bash
# Default output path
safe-pip-compile requirements.in

# Custom output path
safe-pip-compile requirements.in -o requirements/prod.txt
```

**pyproject.toml:**

```toml
[tool.safe-pip-compile]
output-file = "requirements/prod.txt"
```

!!! tip "Separate environments"
    Use different output paths per environment — `requirements/prod.txt`, `requirements/dev.txt` — and run `safe-pip-compile` once per file.

---

## --dry-run

Preview what `safe-pip-compile` would do without writing any files. The full resolution and CVE audit still runs, but the final `requirements.txt` is not written to disk.

```bash
# Basic dry run
safe-pip-compile requirements.in --dry-run

# Dry run with verbose output — see every decision
safe-pip-compile requirements.in --dry-run -v

# Dry run and still generate the JSON report
safe-pip-compile requirements.in --dry-run --json-report audit.json
```

**Use case:** Check which packages would be constrained or blocked before committing the output file to version control.

---

## --json-report

Write a machine-readable JSON vulnerability report to a file. The report includes all detected CVEs, their severity, and whether they were resolved.

**Default:** not set — no report written

**CLI:**

```bash
# Write report to audit.json
safe-pip-compile requirements.in --json-report audit.json

# Report without failing CI on unresolved CVEs
safe-pip-compile requirements.in --no-strict --json-report audit.json
```

**pyproject.toml:**

```toml
[tool.safe-pip-compile]
json-report = "audit.json"
```

**Report structure:**

```json
{
  "resolved": true,
  "iterations": 2,
  "vulnerabilities": [
    {
      "package": "requests",
      "version_found": "2.28.0",
      "version_resolved": "2.31.0",
      "cve_id": "CVE-2023-32681",
      "severity": "high",
      "status": "resolved"
    }
  ]
}
```

**Use case:** Feed into security dashboards, SIEM tools, or archive as a build artifact in CI.

---

## --verbose / -v

Increase the amount of output printed during a run.

| Flag | Level | What you see |
|------|-------|--------------|
| *(none)* | quiet | Final result only |
| `-v` | verbose | Each iteration, packages checked, CVEs found, constraints added |
| `-vv` | extra verbose | Full OSV API responses, constraint calculation details |

```bash
# Verbose — recommended for debugging
safe-pip-compile requirements.in -v

# Extra verbose — full detail
safe-pip-compile requirements.in -vv

# Verbose dry run
safe-pip-compile requirements.in --dry-run -vv
```

**pyproject.toml:**

```toml
[tool.safe-pip-compile]
verbose = 1   # 0 = quiet, 1 = -v, 2 = -vv
```

**Default:** quiet (`0`)
