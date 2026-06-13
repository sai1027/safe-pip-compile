# Cache Management

`safe-pip-compile` maintains a local SQLite database to avoid repeating OSV.dev API calls on every run. The cache covers both CVE vulnerability data and `pip-compile` resolution results.

---

## --no-cache

Disables both the CVE cache and the pip-compile result cache for this single run. All CVE data is fetched live from OSV.dev and `pip-compile` is always called.

```bash
# Bypass cache — always fetch fresh data
safe-pip-compile requirements.in --no-cache

# No-cache with verbose output to see every OSV query
safe-pip-compile requirements.in --no-cache -v
```

**Use case:** When you suspect stale cache data, or when auditing a dependency tree for the first time and want guaranteed fresh results.

---

## --refresh-cache

Clears all existing cached rows from the database, then runs normally — refilling the cache from scratch with fresh data from OSV.dev.

```bash
# Wipe stale cache entries and re-fetch everything
safe-pip-compile requirements.in --refresh-cache

# Refresh cache with a report
safe-pip-compile requirements.in --refresh-cache --json-report audit.json
```

**Difference from `--no-cache`:** `--refresh-cache` permanently clears the cache and refills it during the run. `--no-cache` only skips the cache for one run without deleting anything.

---

## --clear-cache

Deletes the entire cache directory from disk and exits immediately. No compilation or audit is run.

```bash
safe-pip-compile --clear-cache
```

!!! tip "Before uninstalling"
    Run `safe-pip-compile --clear-cache` before `pip uninstall safe-pip-compile` to remove the leftover `cache.db` file from your user profile.

---

## Cache location

| Platform | Path |
|----------|------|
| Linux | `~/.cache/safe-pip-compile/cache.db` |
| macOS | `~/Library/Caches/safe-pip-compile/cache.db` |
| Windows | `%LOCALAPPDATA%\safe-pip-compile\Cache\cache.db` |

The path is per-user, shared across all your virtual environments.

---

## What is cached?

**CVE data:**

- Resolved vulnerabilities (package has a known fix): cached for **6 months**
- Unfixed vulnerabilities (no fix yet): not cached — re-fetched on the next run so newly published fixes are picked up automatically

**pip-compile results:**

- The full resolved dependency set for a given set of input files is cached for **30 minutes**
- The cache key includes the content of all input files and the Python version
- If inputs haven't changed within the window, `pip-compile` is skipped entirely — saving **30–120 seconds** on complex dependency sets

---

## Technical details

- **SQLite WAL mode** — allows multiple concurrent readers without locking
- Cache is per-user, not per-virtualenv — shared across all your projects
- The database is created automatically on first use; no setup required
