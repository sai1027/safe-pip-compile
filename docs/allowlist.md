# CVE Allowlist

Sometimes a vulnerability is known and your team has consciously accepted the risk — for example, because the affected feature is not used, or a fix is not yet available. The allowlist lets you mark specific CVE IDs as accepted so `safe-pip-compile` does not block on them.

---

## --allow-list

Path to a YAML file listing CVE IDs that should be skipped during the audit.

**Default:** not set — no allowlist applied

**CLI:**

```bash
# Use an allowlist file
safe-pip-compile requirements.in --allow-list cve-allowlist.yaml

# Combined with severity filtering
safe-pip-compile requirements.in --allow-list cve-allowlist.yaml --min-severity high

# Allowlist with JSON report to audit what was skipped
safe-pip-compile requirements.in --allow-list cve-allowlist.yaml --json-report audit.json
```

**pyproject.toml:**

```toml
[tool.safe-pip-compile]
allowlist = "cve-allowlist.yaml"
```

!!! warning "Review allowlist entries regularly"
    Allowlist entries should be treated as technical debt. Set an `expires` date and schedule a review, especially if a fix becomes available upstream.

---

## File format

```yaml
allowed_cves:
  - id: CVE-2024-12345
    reason: "Not applicable; we do not use the affected feature"
    expires: 2025-06-01

  - id: GHSA-xxxx-yyyy-zzzz
    reason: "Accepted risk, tracked in JIRA-789"
```

---

## Field reference

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | The vulnerability identifier. Supports CVE, GHSA, and PYSEC IDs. |
| `reason` | Yes | A human-readable explanation for accepting the risk. |
| `expires` | No | Date in `YYYY-MM-DD` format. After this date the CVE will block again. Omit for no expiry. |

---

## How matching works

Allowlist entries are matched against the vulnerability ID **and its aliases**. For example, `CVE-2024-12345` will also match if OSV.dev reports it as a GHSA or PYSEC alias, and vice versa.

---

## Expiry behaviour

- If `expires` is set and today's date is **past** the expiry, the entry is ignored and the CVE blocks as normal.
- If `expires` is **omitted**, the entry never expires.
- Expired entries are logged as a warning so your team can revisit them.

---

## Example: accepting a non-applicable CVE

```yaml
allowed_cves:
  - id: CVE-2023-36810
    reason: >
      Only affects the XML parser path, which we do not invoke.
      Mitigated in our threat model — see security-review-2023-11.md.
    expires: 2024-12-31
```
