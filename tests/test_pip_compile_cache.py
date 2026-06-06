"""Tests for PipCompileCache (30-minute pip-compile result cache)."""
from __future__ import annotations

import os
import time

import pytest

from safe_pip_compile.cache import PipCompileCache


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def pip_cache(tmp_path):
    """An open PipCompileCache backed by a temp SQLite DB."""
    db_path = str(tmp_path / "test_pip_compile_cache.db")
    cache = PipCompileCache(db_path=db_path, ttl_seconds=3600)
    cache.open()
    yield cache
    cache.close()


@pytest.fixture
def req_file(tmp_path):
    """Helper factory: creates a named requirements file and returns its path."""
    def _make(filename: str, content: str) -> str:
        path = tmp_path / filename
        path.write_text(content, encoding="utf-8")
        return str(path)
    return _make


# ---------------------------------------------------------------------------
# Basic store / lookup
# ---------------------------------------------------------------------------

class TestStoreAndLookup:
    def test_miss_on_empty_cache(self, pip_cache, req_file):
        path = req_file("requirements.in", "requests\n")
        key = PipCompileCache.compute_key([path], "3.11.12")
        assert pip_cache.lookup(key) is None

    def test_hit_after_store(self, pip_cache, req_file):
        path = req_file("requirements.in", "requests\n")
        key = PipCompileCache.compute_key([path], "3.11.12")
        packages = ["requests==2.31.0", "urllib3==2.0.7"]

        pip_cache.store(key, packages)

        result = pip_cache.lookup(key)
        assert result is not None
        assert result == packages

    def test_store_overwrites_previous(self, pip_cache, req_file):
        path = req_file("requirements.in", "requests\n")
        key = PipCompileCache.compute_key([path], "3.11.12")

        pip_cache.store(key, ["requests==2.30.0"])
        pip_cache.store(key, ["requests==2.31.0"])

        result = pip_cache.lookup(key)
        assert result == ["requests==2.31.0"]

    def test_empty_package_list_stored_and_retrieved(self, pip_cache, req_file):
        path = req_file("requirements.in", "# empty\n")
        key = PipCompileCache.compute_key([path], "3.11.12")

        pip_cache.store(key, [])
        result = pip_cache.lookup(key)
        assert result == []


# ---------------------------------------------------------------------------
# TTL / expiry
# ---------------------------------------------------------------------------

class TestTTL:
    def test_expired_entry_returns_none(self, tmp_path, req_file):
        db_path = str(tmp_path / "ttl_test.db")
        cache = PipCompileCache(db_path=db_path, ttl_seconds=1)
        cache.open()

        path = req_file("requirements.in", "requests\n")
        key = PipCompileCache.compute_key([path], "3.11.12")
        cache.store(key, ["requests==2.31.0"])

        # Should still be there immediately
        assert cache.lookup(key) is not None

        time.sleep(1.5)

        # Must be expired now
        assert cache.lookup(key) is None

        cache.close()

    def test_purge_expired_removes_old_entries(self, tmp_path, req_file):
        db_path = str(tmp_path / "purge_test.db")
        cache = PipCompileCache(db_path=db_path, ttl_seconds=1)
        cache.open()

        old_path = req_file("old.in", "flask\n")
        new_path = req_file("new.in", "django\n")

        old_key = PipCompileCache.compute_key([old_path], "3.11.12")
        cache.store(old_key, ["flask==3.0.0"])

        time.sleep(1.5)

        new_key = PipCompileCache.compute_key([new_path], "3.11.12")
        cache.store(new_key, ["django==5.0.0"])

        cache.purge_expired()

        assert cache.lookup(old_key) is None
        assert cache.lookup(new_key) == ["django==5.0.0"]

        cache.close()

    def test_clear_removes_all_entries(self, pip_cache, req_file):
        for name, content in [("a.in", "flask\n"), ("b.in", "django\n")]:
            path = req_file(name, content)
            key = PipCompileCache.compute_key([path], "3.11.12")
            pip_cache.store(key, [f"{name}==1.0.0"])

        pip_cache.clear()

        # Both paths use different keys — make sure all are gone
        for name, content in [("a.in", "flask\n"), ("b.in", "django\n")]:
            path = req_file(name, content)
            key = PipCompileCache.compute_key([path], "3.11.12")
            assert pip_cache.lookup(key) is None


# ---------------------------------------------------------------------------
# Cache key sensitivity
# ---------------------------------------------------------------------------

class TestCacheKey:
    def test_key_changes_when_content_changes(self, tmp_path):
        path = tmp_path / "requirements.in"
        path.write_text("requests\n", encoding="utf-8")
        key_before = PipCompileCache.compute_key([str(path)], "3.11.12")

        path.write_text("requests\nflask\n", encoding="utf-8")
        key_after = PipCompileCache.compute_key([str(path)], "3.11.12")

        assert key_before != key_after

    def test_key_changes_when_python_version_changes(self, tmp_path):
        path = tmp_path / "requirements.in"
        path.write_text("requests\n", encoding="utf-8")

        key_311 = PipCompileCache.compute_key([str(path)], "3.11.12")
        key_312 = PipCompileCache.compute_key([str(path)], "3.12.0")

        assert key_311 != key_312

    def test_key_includes_full_patch_version(self, tmp_path):
        """Patch releases produce different keys (e.g. 3.11.11 vs 3.11.12)."""
        path = tmp_path / "requirements.in"
        path.write_text("requests\n", encoding="utf-8")

        key_a = PipCompileCache.compute_key([str(path)], "3.11.11")
        key_b = PipCompileCache.compute_key([str(path)], "3.11.12")

        assert key_a != key_b

    def test_key_is_deterministic(self, tmp_path):
        """Same inputs always produce the same key."""
        path = tmp_path / "requirements.in"
        path.write_text("requests\n", encoding="utf-8")

        key1 = PipCompileCache.compute_key([str(path)], "3.11.12")
        key2 = PipCompileCache.compute_key([str(path)], "3.11.12")

        assert key1 == key2

    def test_key_returns_hex_sha256(self, tmp_path):
        path = tmp_path / "requirements.in"
        path.write_text("requests\n", encoding="utf-8")
        key = PipCompileCache.compute_key([str(path)], "3.11.12")

        # SHA-256 hex digest is 64 chars
        assert len(key) == 64
        assert all(c in "0123456789abcdef" for c in key)

    def test_multi_file_key_is_order_independent(self, tmp_path):
        """Files provided in a different order produce the same key."""
        file_a = tmp_path / "base.in"
        file_b = tmp_path / "dev.in"
        file_a.write_text("requests\n", encoding="utf-8")
        file_b.write_text("pytest\n", encoding="utf-8")

        key_ab = PipCompileCache.compute_key([str(file_a), str(file_b)], "3.11.12")
        key_ba = PipCompileCache.compute_key([str(file_b), str(file_a)], "3.11.12")

        assert key_ab == key_ba

    def test_key_changes_when_filename_changes(self, tmp_path):
        """Two files with the same content but different names get different keys."""
        file_a = tmp_path / "requirements.in"
        file_b = tmp_path / "constraints.in"
        content = "requests\n"
        file_a.write_text(content, encoding="utf-8")
        file_b.write_text(content, encoding="utf-8")

        key_a = PipCompileCache.compute_key([str(file_a)], "3.11.12")
        key_b = PipCompileCache.compute_key([str(file_b)], "3.11.12")

        assert key_a != key_b

    def test_missing_file_yields_stable_key(self, tmp_path):
        """A file that cannot be read still produces a key (no exception)."""
        nonexistent = str(tmp_path / "ghost.in")
        key = PipCompileCache.compute_key([nonexistent], "3.11.12")
        assert len(key) == 64


# ---------------------------------------------------------------------------
# Context manager protocol
# ---------------------------------------------------------------------------

class TestContextManager:
    def test_context_manager_opens_and_closes(self, tmp_path, req_file):
        db_path = str(tmp_path / "ctx_test.db")
        path = req_file("requirements.in", "requests\n")
        key = PipCompileCache.compute_key([path], "3.11.12")

        with PipCompileCache(db_path=db_path) as cache:
            cache.store(key, ["requests==2.31.0"])
            assert cache.lookup(key) == ["requests==2.31.0"]

        # After __exit__, connection must be closed
        assert cache._conn is None
