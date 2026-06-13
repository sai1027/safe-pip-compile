# Network & SSL

Configure how `safe-pip-compile` connects to [OSV.dev](https://osv.dev) — including custom CA certificates for corporate environments.

---

## --cert

Path to a custom CA bundle (PEM format) for SSL verification. Use this when your organisation performs SSL inspection (MITM proxy) and OSV.dev requests fail with a certificate error.

**Default:** auto-detected from environment variables or system certificate store

**CLI:**

```bash
# Use a corporate CA bundle
safe-pip-compile requirements.in --cert /path/to/corporate-ca-bundle.pem

# Windows path
safe-pip-compile requirements.in --cert C:\certs\corp-ca.pem
```

**pyproject.toml:**

```toml
[tool.safe-pip-compile]
cert = "/etc/ssl/certs/corporate-ca.pem"
```

**Environment variable (no flag needed):**

```bash
export SSL_CERT_FILE=/path/to/corporate-ca-bundle.pem
safe-pip-compile requirements.in
```

---

## Certificate lookup order

`safe-pip-compile` resolves the CA bundle in the following priority order:

```
--cert flag  >  SSL_CERT_FILE  >  REQUESTS_CA_BUNDLE  >  CURL_CA_BUNDLE  >  system default
```

The first non-empty value found is used. If none are set, Python's built-in certificate store is used.

---

## Supported environment variables

| Variable | Description |
|----------|-------------|
| `SSL_CERT_FILE` | Path to a PEM-format CA bundle |
| `REQUESTS_CA_BUNDLE` | Same — used by the `requests` library |
| `CURL_CA_BUNDLE` | Same — used by curl |

Setting any of these avoids passing `--cert` on every command.

---

## Getting your corporate CA bundle

Ask your IT or security team for the corporate root CA certificate in PEM format.

**Export on Windows:**

```powershell
# Export all trusted root certificates
certutil -exportPFX Root corp-roots.pfx
# Then convert to PEM with openssl or the Certificates MMC snap-in
```

Alternatively, use the [`truststore`](https://pypi.org/project/truststore/) package to make Python use the system certificate store automatically — no `--cert` flag needed.

---

!!! danger "Disabling SSL verification"
    Never disable SSL verification in production — it exposes you to man-in-the-middle attacks. Always use a proper CA bundle via `--cert` or `SSL_CERT_FILE` instead.
