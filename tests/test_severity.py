from safe_pip_compile.models import Severity
from safe_pip_compile.severity import (
    cvss_score_to_severity,
    extract_severity_from_osv,
    parse_cvss_vector_score,
)


def test_cvss_score_to_severity():
    assert cvss_score_to_severity(9.8) == Severity.CRITICAL
    assert cvss_score_to_severity(9.0) == Severity.CRITICAL
    assert cvss_score_to_severity(7.5) == Severity.HIGH
    assert cvss_score_to_severity(7.0) == Severity.HIGH
    assert cvss_score_to_severity(5.0) == Severity.MEDIUM
    assert cvss_score_to_severity(4.0) == Severity.MEDIUM
    assert cvss_score_to_severity(2.0) == Severity.LOW
    assert cvss_score_to_severity(0.1) == Severity.LOW
    assert cvss_score_to_severity(0.0) == Severity.UNKNOWN


def test_parse_cvss3_vector():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    score = parse_cvss_vector_score(vector)
    assert score is not None
    assert 9.0 <= score <= 10.0


def test_parse_cvss3_low_vector():
    vector = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
    score = parse_cvss_vector_score(vector)
    assert score is not None
    assert score < 4.0


def test_parse_cvss2_vector():
    vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C"
    score = parse_cvss_vector_score(vector)
    assert score is not None
    assert score > 7.0


def test_parse_invalid_vector():
    assert parse_cvss_vector_score("not-a-vector") is None
    assert parse_cvss_vector_score("") is None


def test_extract_severity_from_osv_with_cvss():
    data = {
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        ]
    }
    sev, score = extract_severity_from_osv(data)
    assert sev == Severity.CRITICAL
    assert score is not None


def test_extract_severity_from_ecosystem_specific():
    data = {
        "affected": [
            {
                "ecosystem_specific": {"severity": "HIGH"}
            }
        ]
    }
    sev, score = extract_severity_from_osv(data)
    assert sev == Severity.HIGH
    assert score is None


def test_extract_severity_unknown():
    data = {}
    sev, score = extract_severity_from_osv(data)
    assert sev == Severity.UNKNOWN
    assert score is None


def test_severity_meets_threshold():
    assert Severity.CRITICAL.meets_threshold(Severity.HIGH) is True
    assert Severity.CRITICAL.meets_threshold(Severity.CRITICAL) is True
    assert Severity.HIGH.meets_threshold(Severity.CRITICAL) is False
    assert Severity.MEDIUM.meets_threshold(Severity.LOW) is True
    assert Severity.LOW.meets_threshold(Severity.MEDIUM) is False
    assert Severity.UNKNOWN.meets_threshold(Severity.CRITICAL) is True


def test_severity_from_string():
    assert Severity.from_string("critical") == Severity.CRITICAL
    assert Severity.from_string("HIGH") == Severity.HIGH
    assert Severity.from_string("Medium") == Severity.MEDIUM
    assert Severity.from_string("low") == Severity.LOW
    assert Severity.from_string("garbage") == Severity.UNKNOWN
