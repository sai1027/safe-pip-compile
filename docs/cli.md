# CLI Reference

## Synopsis

```
safe-pip-compile [OPTIONS] SRC_FILE [-- PIP_COMPILE_ARGS...]
```

`SRC_FILE` is your `requirements.in` (or any input file accepted by `pip-compile`).  
Everything after `--` is passed directly to `pip-compile`.

---

## Flags

### Core resolution

| Flag | Default | Description |
|------|---------|-------------|
| `-o, --output-file PATH` | `requirements.txt` | Path to write the compiled output |
| `--min-severity LEVEL` | `low` | Minimum CVE severity to block. One of: `critical`, `high`, `medium`, `low` |
| `--allow-list PATH` | *(none)* | Path to a YAML file of accepted CVEs to skip |
| `--max-iterations INT` | `10` | Maximum compile/audit loops before stopping |
| `--strict / --no-strict` | `--strict` | Exit with code `1` if unresolved CVEs remain |
| `--no-cve` | off | Skip CVE checking entirely — pure `pip-compile` pass-through |

### Output & reporting

| Flag | Default | Description |
|------|---------|-------------|
| `--dry-run` | off | Preview actions without writing any output files |
| `--json-report PATH` | *(none)* | Write a machine-readable JSON vulnerability report |
| `-v, --verbose` | quiet | Increase output detail. Use `-v` (verbose) or `-vv` (extra verbose) |

### Cache

| Flag | Default | Description |
|------|---------|-------------|
| `--no-cache` | off | Disable the local CVE cache and always query OSV.dev |
| `--refresh-cache` | off | Clear all cached CVE data and re-fetch from OSV.dev, then run normally |
| `--clear-cache` | off | Delete the entire cache directory and exit |

### Network & SSL

| Flag | Default | Description |
|------|---------|-------------|
| `--cert PATH` | *(auto)* | CA bundle for SSL verification (useful behind corporate proxies) |

---

## Examples

### Basic compile

```bash
safe-pip-compile requirements.in -o requirements.txt
```

### Block only high and critical vulnerabilities

```bash
safe-pip-compile requirements.in --min-severity high
```

### Use a CVE allowlist

```bash
safe-pip-compile requirements.in --allow-list cve-allowlist.yaml
```

### Generate a JSON report and fail CI on unresolved CVEs

```bash
safe-pip-compile requirements.in --json-report audit.json --strict
```

### Preview without writing files

```bash
safe-pip-compile requirements.in --dry-run -v
```

### Skip CVE checking (pure pip-compile)

```bash
safe-pip-compile requirements.in --no-cve
```

### Cache management

```bash
# Force fresh CVE data for this run
safe-pip-compile requirements.in --no-cache

# Clear stale cache rows and re-fetch
safe-pip-compile requirements.in --refresh-cache

# Wipe the entire cache directory (e.g. before uninstalling)
safe-pip-compile --clear-cache
```

### Verbose output

```bash
safe-pip-compile requirements.in -v    # verbose
safe-pip-compile requirements.in -vv   # extra verbose
```

### Pass flags to pip-compile

```bash
safe-pip-compile requirements.in -- --generate-hashes --allow-unsafe
```

---

## Using behind a corporate proxy

```bash
safe-pip-compile requirements.in --cert /path/to/corporate-ca-bundle.pem
```

See [Corporate Proxy & SSL](proxy.md) for full details.
