# CVE Allowlist

Sometimes a vulnerability is known and your team has consciously accepted the risk — for example, because the affected feature is not used, or a fix is not yet available. The allowlist lets you mark specific CVE IDs as accepted so `safe-pip-compile` does not block on them.

---

## Enabling the allowlist

=== "CLI"

    ```bash
    safe-pip-compile requirements.in --allow-list cve-allowlist.yaml
    ```

=== "pyproject.toml"

    ```toml
    [tool.safe-pip-compile]
    allowlist = "cve-allowlist.yaml"
    ```

---

## File format

```yaml title="cve-allowlist.yaml"
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
| `id` | ✅ Yes | The vulnerability identifier to allow. Supports CVE, GHSA, and PYSEC IDs. |
| `reason` | ✅ Yes | A human-readable explanation for accepting the risk. |
| `expires` | ❌ No | Date in `YYYY-MM-DD` format. After this date the entry is treated as expired and the CVE will block again. Omit for no expiry. |

---

## How matching works

Allowlist entries are matched against the vulnerability ID **and its aliases**. For example, a CVE ID like `CVE-2024-12345` will also match if OSV.dev reports it as a GHSA or PYSEC alias, and vice versa.

---

## Expiry behaviour

- If `expires` is set and today's date is **past** the expiry, the entry is ignored and the CVE will block as normal.
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

---

!!! warning "Review allowlist entries regularly"
    Allowlist entries should be treated as technical debt. Set an `expires` date and schedule a review, especially if a fix becomes available upstream.
