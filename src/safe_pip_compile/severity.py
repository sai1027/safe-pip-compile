from __future__ import annotations

from safe_pip_compile.models import Severity


def cvss_score_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    elif score >= 7.0:
        return Severity.HIGH
    elif score >= 4.0:
        return Severity.MEDIUM
    elif score >= 0.1:
        return Severity.LOW
    return Severity.UNKNOWN


def parse_cvss_vector_score(vector: str) -> float | None:
    """Extract base score from a CVSS vector string.

    Handles CVSS v3.x and v2 vectors. Returns None if unparseable.
    """
    vector = vector.strip()

    if vector.startswith("CVSS:3"):
        return _parse_cvss3_score(vector)
    elif vector.startswith("CVSS:4"):
        return _parse_cvss4_score(vector)
    elif "/" in vector and not vector.startswith("CVSS:"):
        return _parse_cvss2_score(vector)

    return None


def _parse_cvss3_score(vector: str) -> float | None:
    metrics = {}
    parts = vector.split("/")
    for part in parts:
        if ":" in part:
            key, val = part.split(":", 1)
            metrics[key] = val

    av_scores = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    ac_scores = {"L": 0.77, "H": 0.44}
    pr_scores_u = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_scores_c = {"N": 0.85, "L": 0.68, "H": 0.50}
    ui_scores = {"N": 0.85, "R": 0.62}
    cia_scores = {"H": 0.56, "L": 0.22, "N": 0.0}
    scope_changed = metrics.get("S") == "C"

    try:
        av = av_scores[metrics["AV"]]
        ac = ac_scores[metrics["AC"]]
        pr_map = pr_scores_c if scope_changed else pr_scores_u
        pr = pr_map[metrics["PR"]]
        ui = ui_scores[metrics["UI"]]
        c = cia_scores[metrics["C"]]
        i = cia_scores[metrics["I"]]
        a = cia_scores[metrics["A"]]
    except KeyError:
        return None

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0

    if scope_changed:
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)

    return _roundup(base)


def _parse_cvss4_score(vector: str) -> float | None:
    # CVSS v4 scoring is complex; approximate from metrics
    metrics = {}
    parts = vector.split("/")
    for part in parts:
        if ":" in part:
            key, val = part.split(":", 1)
            metrics[key] = val

    high_indicators = 0
    if metrics.get("AV") == "N":
        high_indicators += 2
    if metrics.get("AC") == "L":
        high_indicators += 1
    if metrics.get("AT") == "N":
        high_indicators += 1
    for m in ["VC", "VI", "VA"]:
        if metrics.get(m) == "H":
            high_indicators += 1

    total_metrics = 7
    ratio = high_indicators / total_metrics
    score = 1.0 + ratio * 9.0
    return round(score, 1)


def _parse_cvss2_score(vector: str) -> float | None:
    metrics = {}
    parts = vector.split("/")
    for part in parts:
        if ":" in part:
            key, val = part.split(":", 1)
            metrics[key] = val

    av_scores = {"N": 1.0, "A": 0.646, "L": 0.395}
    ac_scores = {"L": 0.71, "M": 0.61, "H": 0.35}
    au_scores = {"N": 0.704, "S": 0.56, "M": 0.45}
    cia_scores = {"C": 0.660, "P": 0.275, "N": 0.0}

    try:
        av = av_scores[metrics["AV"]]
        ac = ac_scores[metrics["AC"]]
        au = au_scores[metrics["Au"]]
        c = cia_scores[metrics["C"]]
        i = cia_scores[metrics["I"]]
        a = cia_scores[metrics["A"]]
    except KeyError:
        return None

    impact = 10.41 * (1 - (1 - c) * (1 - i) * (1 - a))
    exploitability = 20 * av * ac * au

    if impact == 0:
        return 0.0

    base = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * 1.176
    return round(min(base, 10.0), 1)


def _roundup(value: float) -> float:
    """Round up to one decimal place per CVSS spec."""
    import math
    return math.ceil(value * 10) / 10


def extract_severity_from_osv(vuln_data: dict) -> tuple[Severity, float | None]:
    severity_list = vuln_data.get("severity", [])
    for entry in severity_list:
        score_type = entry.get("type", "")
        score_val = entry.get("score", "")

        if score_type in ("CVSS_V3", "CVSS_V4", "CVSS_V2"):
            parsed = parse_cvss_vector_score(score_val)
            if parsed is not None:
                return cvss_score_to_severity(parsed), parsed

    for affected in vuln_data.get("affected", []):
        eco_specific = affected.get("ecosystem_specific", {})
        sev_str = eco_specific.get("severity", "")
        if sev_str:
            sev = Severity.from_string(sev_str)
            if sev != Severity.UNKNOWN:
                return sev, None

        db_specific = affected.get("database_specific", {})
        sev_str = db_specific.get("severity", "")
        if sev_str:
            sev = Severity.from_string(sev_str)
            if sev != Severity.UNKNOWN:
                return sev, None

    db_specific = vuln_data.get("database_specific", {})
    sev_str = db_specific.get("severity", "")
    if sev_str:
        sev = Severity.from_string(sev_str)
        if sev != Severity.UNKNOWN:
            return sev, None

    return Severity.UNKNOWN, None
