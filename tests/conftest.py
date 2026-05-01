import os

import pytest

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture
def fixtures_dir():
    return FIXTURES_DIR


@pytest.fixture
def sample_requirements_path(fixtures_dir):
    return os.path.join(fixtures_dir, "sample_requirements.txt")


@pytest.fixture
def sample_osv_batch_path(fixtures_dir):
    return os.path.join(fixtures_dir, "sample_osv_batch.json")


@pytest.fixture
def sample_osv_vuln_path(fixtures_dir):
    return os.path.join(fixtures_dir, "sample_osv_vuln.json")


@pytest.fixture
def sample_allowlist_path(fixtures_dir):
    return os.path.join(fixtures_dir, "sample_allowlist.yaml")
