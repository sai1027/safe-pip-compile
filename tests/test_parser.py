import os
import tempfile

from safe_pip_compile.parser import parse_requirements


def test_parse_sample_requirements(sample_requirements_path):
    packages = parse_requirements(sample_requirements_path)
    names = {p.name for p in packages}
    assert "django" in names
    assert "requests" in names
    assert "urllib3" in names
    assert "asgiref" in names
    assert len(packages) == 8


def test_parse_pinned_versions(sample_requirements_path):
    packages = parse_requirements(sample_requirements_path)
    pkg_map = {p.name: p.version for p in packages}
    assert pkg_map["django"] == "3.2.1"
    assert pkg_map["requests"] == "2.28.0"
    assert pkg_map["urllib3"] == "1.26.15"


def test_parse_skips_comments_and_blanks():
    content = "# comment\n\ndjango==4.2.7\n# via something\nrequests==2.31.0\n"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(content)
        f.flush()
        path = f.name

    try:
        packages = parse_requirements(path)
        assert len(packages) == 2
        assert packages[0].name == "django"
        assert packages[1].name == "requests"
    finally:
        os.unlink(path)


def test_parse_with_extras():
    content = "psycopg2[binary]==2.9.9\n"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(content)
        f.flush()
        path = f.name

    try:
        packages = parse_requirements(path)
        assert len(packages) == 1
        assert packages[0].name == "psycopg2"
        assert packages[0].extras == ("binary",)
        assert packages[0].version == "2.9.9"
    finally:
        os.unlink(path)


def test_parse_with_hashes():
    content = (
        "django==4.2.7 \\\n"
        "    --hash=sha256:abc123 \\\n"
        "    --hash=sha256:def456\n"
        "requests==2.31.0 \\\n"
        "    --hash=sha256:ghi789\n"
    )
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(content)
        f.flush()
        path = f.name

    try:
        packages = parse_requirements(path)
        assert len(packages) == 2
        assert packages[0].name == "django"
        assert packages[0].version == "4.2.7"
    finally:
        os.unlink(path)


def test_parse_normalizes_names():
    content = "Django_Rest_Framework==3.14.0\n"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(content)
        f.flush()
        path = f.name

    try:
        packages = parse_requirements(path)
        assert len(packages) == 1
        assert packages[0].name == "django-rest-framework"
    finally:
        os.unlink(path)


def test_parse_skips_options():
    content = "--index-url https://pypi.org/simple\ndjango==4.2.7\n"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(content)
        f.flush()
        path = f.name

    try:
        packages = parse_requirements(path)
        assert len(packages) == 1
        assert packages[0].name == "django"
    finally:
        os.unlink(path)
