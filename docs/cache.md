# Local CVE Cache

`safe-pip-compile` maintains a local SQLite database to avoid repeating OSV.dev API calls on every run. The cache covers both vulnerability data and `pip-compile` resolution results.

---

## Cache location

| Platform | Path |
|----------|------|
| Linux | `~/.cache/safe-pip-compile/cache.db` |
| macOS | `~/Library/Caches/safe-pip-compile/cache.db` |
| Windows | `%LOCALAPPDATA%\safe-pip-compile\Cache\cache.db` |

The path is determined by the [`platformdirs`](https://pypi.org/project/platformdirs/) library and is per-user, so it works across virtual environments.

---

## What is cached?

### CVE data
- **Resolved vulnerabilities** (package has a known fix): cached for **6 months**
- **Unfixed vulnerabilities** (no fix available yet): **not cached permanently** — re-fetched on the next run so a newly published fix is picked up automatically

### pip-compile results
- The full resolved dependency set for a given set of input files is cached for **30 minutes**
- The cache key includes the content of all input files and the Python version
- If inputs haven't changed within the window, `pip-compile` is skipped entirely and CVE scanning starts immediately — saving **30–120 seconds** on complex dependency sets

---

## Cache management flags

| Flag | What it does |
|------|-------------|
| `--no-cache` | Disables **both** the CVE cache and the pip-compile result cache for this run. All data is fetched live from OSV.dev. |
| `--refresh-cache` | Deletes all cached rows with a SQL `DELETE`, then runs normally and refills the cache from scratch. |
| `--clear-cache` | Deletes the entire cache **directory** from disk (`shutil.rmtree`) and exits immediately. Useful before uninstalling. |

```bash
# Skip the cache for this run only
safe-pip-compile requirements.in --no-cache

# Wipe stale entries and re-fetch
safe-pip-compile requirements.in --refresh-cache

# Remove the cache directory entirely
safe-pip-compile --clear-cache
```

---

## Technical details

- **SQLite WAL mode** — allows multiple concurrent readers without locking
- Cache is stored per-user, not per-virtualenv — shared across all your projects
- The database is created automatically on first use; no setup required

---

!!! tip "Before uninstalling"
    Run `safe-pip-compile --clear-cache` before `pip uninstall safe-pip-compile` to remove the leftover `cache.db` file from your user profile.
