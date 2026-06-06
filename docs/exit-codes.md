# Exit Codes

`safe-pip-compile` uses distinct exit codes so CI pipelines can distinguish between different failure modes.

| Code | Meaning |
|------|---------|
| `0` | ✅ Clean result — no blocking CVEs found in the final output |
| `1` | ⚠️ Unresolved CVEs remain in the final output (only in `--strict` mode) |
| `2` | ❌ `pip-compile` resolution failed (e.g. conflicting requirements) |
| `3` | 🌐 Network or configuration error (e.g. OSV.dev unreachable, bad CA bundle) |

---

## CI usage

In GitHub Actions (and most CI systems), any non-zero exit code fails the step:

```yaml
- name: Compile safe requirements
  run: safe-pip-compile requirements.in --strict
```

To allow unresolved CVEs without failing CI (e.g. to generate a report only):

```bash
safe-pip-compile requirements.in --no-strict --json-report audit.json
```

---

## Checking the exit code in shell

```bash
safe-pip-compile requirements.in
if [ $? -eq 1 ]; then
  echo "Unresolved CVEs detected!"
fi
```
