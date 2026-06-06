# Corporate Proxy & SSL

If your organization performs SSL inspection (MITM), OSV.dev requests may fail with a certificate verification error. `safe-pip-compile` supports custom CA bundles to handle this.

---

## Using a custom CA bundle

=== "CLI flag"

    ```bash
    safe-pip-compile requirements.in --cert /path/to/corporate-ca-bundle.pem
    ```

=== "pyproject.toml"

    ```toml
    [tool.safe-pip-compile]
    cert = "/etc/ssl/certs/corporate-ca.pem"
    ```

=== "Environment variable"

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

The first non-empty value found is used. If none are set, the system's default certificate store is used.

---

## Supported environment variables

| Variable | Description |
|----------|-------------|
| `SSL_CERT_FILE` | Path to a PEM-format CA bundle |
| `REQUESTS_CA_BUNDLE` | Same as above (used by the `requests` library) |
| `CURL_CA_BUNDLE` | Same as above (used by curl) |

---

## Disabling SSL verification

!!! danger "Not recommended"
    Disabling SSL verification exposes you to man-in-the-middle attacks. Use a proper CA bundle instead.

If you absolutely must disable verification (e.g., in a sandboxed test environment), you can set:

```bash
export HTTPX_DISABLE_SSL_VERIFY=1  # not an official httpx variable — see note below
```

The recommended approach is always to provide the correct CA bundle.

---

## Getting your corporate CA bundle

Ask your IT/security team for the corporate root CA certificate in PEM format. On many corporate machines it may already be installed system-wide; the issue is that Python's `ssl` module uses its own bundled certificates by default.

A quick way to export the system cert store on Windows:

```powershell
# Export all trusted root certificates to a PEM file
certutil -exportPFX Root corp-roots.pfx
# (then convert with openssl or use the PEM export option)
```

Or use the [`truststore`](https://pypi.org/project/truststore/) package to make Python use the system certificate store automatically.
