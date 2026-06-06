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

## Next steps

- [CLI Reference](cli.md) — all available flags
- [Configuration](configuration.md) — set defaults in `pyproject.toml`
- [CVE Allowlist](allowlist.md) — accept specific known CVEs
