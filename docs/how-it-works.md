# How It Works

`safe-pip-compile` wraps `pip-compile` with an iterative CVE-aware resolution loop powered by the [OSV.dev](https://osv.dev) vulnerability database.

---

## Resolution loop

```
requirements.in
  → pip-compile                        # resolve full dependency tree
  → parse resolved packages            # extract name + version pairs
  → check local cache or query OSV.dev # fetch vulnerability data
  → filter by severity and allowlist   # skip low-severity or accepted CVEs
  → add temporary constraints          # e.g. django>=3.2.25
  → pip-compile (again)                # re-resolve with constraints
  → repeat until clean, stuck, or max iterations reached
  → requirements.txt
```

---

## Step-by-step

### 1. Initial resolution

`pip-compile` is called with your `requirements.in` to produce a fully pinned dependency tree.

### 2. CVE audit

Every resolved package (`name==version`) is checked against [OSV.dev](https://osv.dev) — either from the local SQLite cache (fast) or via the OSV Batch API (network). This gives a list of known vulnerabilities for each package version.

### 3. Filtering

Vulnerabilities are filtered by:

- **Severity** — only CVEs at or above `--min-severity` are considered blocking
- **Allowlist** — CVEs listed in the allowlist (and not expired) are skipped

### 4. Constraint injection

For each blocking CVE, `safe-pip-compile` determines the minimum safe version (i.e., the version where the fix was introduced) and writes a temporary lower-bound constraint:

```
django>=3.2.25
requests>=2.31.0
```

These constraints are passed to the next `pip-compile` invocation.

### 5. Re-resolution

`pip-compile` runs again with the new constraints. The resolver finds the next version that satisfies both your requirements **and** the safety constraints.

### 6. Termination

The loop ends when:

- ✅ **Clean** — no blocking CVEs remain in the resolved set
- 🔁 **Stuck** — the same set of CVEs appears twice in a row (the resolver cannot escape them)
- 🔢 **Limit reached** — `--max-iterations` is exceeded

In strict mode (`--strict`, the default), a non-zero exit code is returned if CVEs remain at the end.

---

## Why iterate instead of hand-edit?

Traditional approaches involve manually editing `requirements.txt` to bump a package version. This breaks repeatability — the file is no longer the output of a clean resolve. `safe-pip-compile` keeps `pip-compile` in control of the full dependency graph, so transitive dependencies are properly re-evaluated every time a constraint changes.

---

## OSV.dev

[OSV.dev](https://osv.dev) is an open vulnerability database maintained by Google. It aggregates data from NVD, GitHub Advisory Database, PyPI advisories, and more. `safe-pip-compile` uses the public batch API — no API key required.
